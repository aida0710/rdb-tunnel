#[derive(Debug, Clone)]
pub enum IPHeaderViolation {
    UnknownProtocol, // protocol >= 143
    LandAttack,      // source IP = dest IP
    ShortHeader,     // header length < length field
    MalformedPacket, // actual length != length field
}

#[derive(Debug, Clone)]
pub enum IPOptionViolation {
    MalformedOption, // 不正な構造
    SecurityOption,  // Security and handling restriction
    LooseRouting,    // Loose source routing
    RecordRoute,     // Record route
    StreamId,        // Stream identifier
    StrictRouting,   // Strict source routing
    Timestamp,       // Internet timestamp
}

#[derive(Debug, Clone)]
pub enum FragmentViolation {
    //  FragmentStorm,     // 大量のフラグメント
    LargeOffset, // 大きなオフセット値
    // TooManyFragments,  // 過剰な分割数
    // Teardrop,          // teardrop攻撃
    SameOffset,      // オフセット値の重複
    InvalidFragment, // その他の不正フラグメント
}

#[derive(Debug, Clone)]
pub enum ICMPViolation {
    SourceQuench,     // source quench
    TimestampRequest, // timestamp request
    TimestampReply,   // timestamp reply
    InfoRequest,      // information request
    InfoReply,        // information reply
    MaskRequest,      // address mask request
    MaskReply,        // address mask reply
    TooLarge,         // > 1024 bytes
}

#[derive(Debug, Clone)]
pub enum UDPViolation {
    ShortHeader, // length < 8
    Bomb,        // length too large
}

#[derive(Debug, Clone)]
pub enum TCPViolation {
    NoBitsSet, // フラグなし
    SynAndFin, // SYN + FIN同時設定
    FinNoAck,  // ACKなしのFIN
}

#[derive(Debug, Clone)]
pub enum FTPViolation {
    ImproperPort, // port not in 1024-65535
}

#[derive(Debug, Clone)]
pub struct DetectionRules {
    pub ip_header: Vec<IPHeaderViolation>,
    pub ip_option: Vec<IPOptionViolation>,
    pub fragment: Vec<FragmentViolation>,
    pub icmp: Vec<ICMPViolation>,
    pub udp: Vec<UDPViolation>,
    pub tcp: Vec<TCPViolation>,
    pub ftp: Vec<FTPViolation>,
}
