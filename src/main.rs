use std::net::{Ipv4Addr, UdpSocket};
use std::str;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct ByteBuffer {
    buf: [u8; 512],
    pos: usize,
}

impl ByteBuffer {
    fn new() -> Self {
        ByteBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn seek(&mut self, new_pos: usize) {
        self.pos = new_pos;
    }

    fn data(&self) -> &[u8] {
        &self.buf[0..self.pos]
    }

    fn read_byte(&mut self) -> u8 {
        let data = self.buf[self.pos];
        self.pos += 1;
        return data;
    }

    fn peek_byte(&self) -> u8 {
        self.buf[self.pos + 1]
    }

    fn read_two_bytes(&mut self) -> u16 {
        (self.read_byte() as u16) << 8 | (self.read_byte() as u16)
    }

    fn read_four_bytes(&mut self) -> u32 {
        (self.read_two_bytes() as u32) << 16 | (self.read_two_bytes() as u32)
    }

    fn read_labels(&mut self) -> String {
        let mut data = Vec::new();

        // TODO this will fail if we encounter a nested loop
        let mut jumped = false;
        let mut final_position = self.pos;

        loop {
            let length = self.read_byte();

            // if the two highest bits are set then this is a jump
            let jump = ((length & 0xC0) >> 6) != 0;
            // DNS can contain malicious payloads
            // TODO guard against infinite loops
            if jump {
                // jump position is denoted by value of u16 when jump flag bits are ignored
                let jump_position = (((length as u16) << 8) | (self.read_byte() as u16)) & 0x3FFF;
                // track starting position
                final_position = self.pos;
                // move to jump position and restart loop
                self.seek(jump_position as usize);
                jumped = true;
                continue;
            } else {
                for _ in 0..length {
                    data.push(self.read_byte())
                }
                // if next byte is termination null byte then labels are complete
                if self.peek_byte() == 0 {
                    // pop off null byte and exit loop
                    self.read_byte();
                    break;
                };
                // add a period as joiner
                data.push(46)
            }
        }

        if jumped {
            self.seek(final_position)
        }

        // TODO return a result to remove unwrap
        str::from_utf8(&data).unwrap().to_string()
    }

    fn write(&mut self, data: u8) {
        self.buf[self.pos] = data;
        self.pos += 1;
    }

    fn write_two_bytes(&mut self, data: u16) {
        self.write((data >> 8) as u8);
        self.write((data & 0xFF) as u8);
    }

    fn write_labels(&mut self, labels: &String) {
        for name in labels.split(".") {
            let len = name.len();
            // TODO check that name does not exceed max size
            self.write(len as u8);
            for byte in name.as_bytes() {
                self.write(*byte);
            }
        }
        self.write(0)
    }
}

#[derive(Debug)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

/*
| RFC Name | Descriptive Name     | Length    | Description                                                                                                                                                                         |
| -------- | -------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID       | Packet Identifier    | 16 bits   | A random identifier is assigned to query packets. Response packets must reply with the same id. This is needed to differentiate responses due to the stateless nature of UDP.       |
| QR       | Query Response       | 1 bit     | 0 for queries, 1 for responses.                                                                                                                                                     |
| OPCODE   | Operation Code       | 4 bits    | Typically always 0, see RFC1035 for details.                                                                                                                                        |
| AA       | Authoritative Answer | 1 bit     | Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.                                                                                       |
| TC       | Truncated Message    | 1 bit     | Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.                     |
| RD       | Recursion Desired    | 1 bit     | Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.                                     |
| RA       | Recursion Available  | 1 bit     | Set by the server to indicate whether or not recursive queries are allowed.                                                                                                         |
| Z        | Reserved             | 3 bits    | Originally reserved for later use, but now used for DNSSEC queries.                                                                                                                 |
| RCODE    | Response Code        | 4 bits    | Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure. |
| QDCOUNT  | Question Count       | 16 bits   | The number of entries in the Question Section                                                                                                                                       |
| ANCOUNT  | Answer Count         | 16 bits   | The number of entries in the Answer Section                                                                                                                                         |
| NSCOUNT  | Authority Count      | 16 bits   | The number of entries in the Authority Section                                                                                                                                      |
| ARCOUNT  | Additional Count     | 16 bits   | The number of entries in the Additional Section
*/
#[derive(Debug)]
struct DnsHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: ResultCode,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    pub fn new() -> Self {
        DnsHeader {
            id: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .subsec_nanos() as u16,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: ResultCode::NOERROR,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn from_buffer(buffer: &mut ByteBuffer) -> Self {
        let id = buffer.read_two_bytes();
        let flags = buffer.read_two_bytes();
        let qdcount = buffer.read_two_bytes();
        let ancount = buffer.read_two_bytes();
        let nscount = buffer.read_two_bytes();
        let arcount = buffer.read_two_bytes();

        DnsHeader {
            id,
            qr: flags & (1 << 15) != 0,
            opcode: ((flags >> 11) & 0x0F) as u8,
            aa: flags & (1 << 10) != 0,
            tc: flags & (1 << 9) != 0,
            rd: flags & (1 << 8) != 0,
            ra: flags & (1 << 7) != 0,
            z: ((flags >> 4) & 0x07) as u8,
            rcode: ResultCode::from_num((flags & 0x000F) as u8),
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    pub fn to_buffer(&self, buffer: &mut ByteBuffer) {
        buffer.write_two_bytes(self.id);
        let mut flags = 0;
        // TODO this does not handle server-set fields
        if self.qr {
            flags |= 0b1000_0000_0000_0000
        }
        if self.aa {
            flags |= 0b0000_0100_0000_0000
        }
        if self.tc {
            flags |= 0b0000_0010_0000_0000
        }
        if self.rd {
            flags |= 0b0000_0001_0000_0000
        }
        if self.ra {
            flags |= 0b0000_0000_1000_0000
        }
        buffer.write_two_bytes(flags);
        buffer.write_two_bytes(self.qdcount);
        buffer.write_two_bytes(self.ancount);
        buffer.write_two_bytes(self.nscount);
        buffer.write_two_bytes(self.arcount);
    }
}

#[derive(Debug)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
}

impl QueryType {
    fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            _ => QueryType::UNKNOWN(num),
        }
    }

    fn to_num(&self) -> u16 {
        match &self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            _ => 0,
        }
    }
}

/*
| Field  | Type           | Description                                                          |
| ------ | -------------- | -------------------------------------------------------------------- |
| Name   | Label Sequence | The domain name, encoded as a sequence of labels as described below. |
| Type   | 2-byte Integer | The record type.                                                     |
| Class  | 2-byte Integer | The class, in practice always set to 1.                              |
*/
#[derive(Debug)]
struct DnsQuestion {
    name: String,
    qtype: QueryType,
    class: u16,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        DnsQuestion {
            name,
            qtype,
            class: 1,
        }
    }

    pub fn from_buffer(buffer: &mut ByteBuffer) -> Self {
        let name = buffer.read_labels();
        let qtype = QueryType::from_num(buffer.read_two_bytes());
        let class = buffer.read_two_bytes();

        DnsQuestion { name, qtype, class }
    }

    pub fn to_buffer(&self, buffer: &mut ByteBuffer) {
        buffer.write_labels(&self.name);
        buffer.write_two_bytes(self.qtype.to_num());
        buffer.write_two_bytes(self.class)
    }
}

/*
| Field  | Type           | Description                                                                       |
| ------ | -------------- | --------------------------------------------------------------------------------- |
| Name   | Label Sequence | The domain name, encoded as a sequence of labels as described below.              |
| Type   | 2-byte Integer | The record type.                                                                  |
| Class  | 2-byte Integer | The class, in practice always set to 1.                                           |
| TTL    | 4-byte Integer | Time-To-Live, i.e. how long a record can be cached before it should be re-queried.|
| Len    | 2-byte Integer | Length of the record type specific data.                                          |
*/
#[derive(Debug)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: QueryType,
        len: u16,
        ttl: u32,
    }, // 0
    /*
    | Field      | Type            | Description                                                                       |
    | ---------- | --------------- | --------------------------------------------------------------------------------- |
    | Preamble   | Record Preamble | The record preamble, as described above, with the length field set to 4.          |
    | IP         | 4-byte Integer  | An IP-address encoded as a four byte integer.                                     |
    */
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    /*
    | Field      | Type            | Description                                                                       |
    | ---------- | --------------- | --------------------------------------------------------------------------------- |
    | Preamble   | Record Preamble | The record preamble, as described above                                           |
    | Host       | Label           | The Name Server for the domain, as a label sequence                               |
    */
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    /*
    | Field      | Type            | Description                                                                       |
    | ---------- | --------------- | --------------------------------------------------------------------------------- |
    | Preamble   | Record Preamble | The record preamble, as described above                                           |
    | Host       | Label           | The Canonical Name for the domain, as a label sequence                            |
    */
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
}

impl DnsRecord {
    fn from_buffer(buffer: &mut ByteBuffer) -> Self {
        let domain = buffer.read_labels();
        let qtype = QueryType::from_num(buffer.read_two_bytes());
        let _class = buffer.read_two_bytes();
        let ttl = buffer.read_four_bytes();
        let len = buffer.read_two_bytes();

        match qtype {
            QueryType::A => {
                let addr = Ipv4Addr::new(
                    buffer.read_byte(),
                    buffer.read_byte(),
                    buffer.read_byte(),
                    buffer.read_byte(),
                );
                DnsRecord::A { domain, addr, ttl }
            }
            QueryType::NS => {
                let host = buffer.read_labels();
                DnsRecord::NS { domain, host, ttl }
            }
            QueryType::CNAME => {
                let host = buffer.read_labels();
                DnsRecord::CNAME { domain, host, ttl }
            }
            QueryType::UNKNOWN(_) => DnsRecord::UNKNOWN {
                domain,
                qtype,
                len,
                ttl,
            },
        }
    }
}

// | Section            | Size     | Type              | Purpose                                                                                                |
// | ------------------ | -------- | ----------------- | ------------------------------------------------------------------------------------------------------ |
// | Header             | 12 Bytes | Header            | Information about the query/response.                                                                  |
// | Question Section   | Variable | List of Questions | In practice only a single question indicating the query name (domain) and the record type of interest. |
// | Answer Section     | Variable | List of Records   | The relevant records of the requested type.                                                            |
// | Authority Section  | Variable | List of Records   | An list of name servers (NS records), used for resolving queries recursively.                          |
// | Additional Section | Variable | List of Records   | Additional records, that might be useful. For instance, the corresponding A records for NS records.    |
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additional: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut ByteBuffer) -> Self {
        let header = DnsHeader::from_buffer(buffer);
        let mut questions: Vec<DnsQuestion> = Vec::new();
        let mut answers: Vec<DnsRecord> = Vec::new();
        let mut authorities: Vec<DnsRecord> = Vec::new();
        let mut additional: Vec<DnsRecord> = Vec::new();

        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::from_buffer(buffer));
        }

        for _ in 0..header.ancount {
            answers.push(DnsRecord::from_buffer(buffer));
        }

        for _ in 0..header.nscount {
            authorities.push(DnsRecord::from_buffer(buffer));
        }

        for _ in 0..header.arcount {
            additional.push(DnsRecord::from_buffer(buffer));
        }

        DnsPacket {
            header,
            questions,
            answers,
            authorities,
            additional,
        }
    }

    pub fn to_buffer(&mut self, buffer: &mut ByteBuffer) {
        self.header.qdcount = self.questions.len() as u16;
        self.header.ancount = self.answers.len() as u16;
        self.header.nscount = self.authorities.len() as u16;
        self.header.arcount = self.additional.len() as u16;

        self.header.to_buffer(buffer);

        for question in &self.questions {
            question.to_buffer(buffer);
        }
    }
}

fn main() {
    let qname = std::env::args().nth(1).expect("no domain name given");

    // TODO allow this to be passed in as a CLI arg
    let qtype = QueryType::A;

    // Using cloudflare's public DNS server
    let server = ("1.1.1.1", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 44444)).expect("unable to bind to UDP port 44444");

    let mut packet = DnsPacket::new();

    packet.header.rd = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut buffer = ByteBuffer::new();
    packet.to_buffer(&mut buffer);

    // Send packet to the server using our socket:
    socket.send_to(buffer.data(), server).unwrap();

    let mut buffer = ByteBuffer::new();
    socket.recv_from(&mut buffer.buf).unwrap();

    let packet = DnsPacket::from_buffer(&mut buffer);
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.additional {
        println!("{:#?}", rec);
    }
}
