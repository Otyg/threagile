package model

type Protocol int

const (
	UnknownProtocol Protocol = iota
	HTTP
	HTTPS
	WS
	WSS
	Reverse_proxy_web_protocol
	Reverse_proxy_web_protocol_encrypted
	MQTT
	JDBC
	JDBC_encrypted
	ODBC
	ODBC_encrypted
	SQL_access_protocol
	SQL_access_protocol_encrypted
	NoSQL_access_protocol
	NoSQL_access_protocol_encrypted
	BINARY
	BINARY_encrypted
	TEXT
	TEXT_encrypted
	SSH
	SSH_tunnel
	SMTP
	SMTP_encrypted
	POP3
	POP3_encrypted
	IMAP
	IMAP_encrypted
	FTP
	FTPS
	SFTP
	SCP
	LDAP
	LDAPS
	JMS
	NFS
	SMB
	SMB_encrypted
	LocalFileAccess
	NRPE
	XMPP
	IIOP
	IIOP_encrypted
	JRMP
	JRMP_encrypted
	InProcessLibraryCall
	ContainerSpawning
)

func ProtocolValues() []TypeEnum {
	return []TypeEnum{
		UnknownProtocol,
		HTTP,
		HTTPS,
		WS,
		WSS,
		Reverse_proxy_web_protocol,
		Reverse_proxy_web_protocol_encrypted,
		MQTT,
		JDBC,
		JDBC_encrypted,
		ODBC,
		ODBC_encrypted,
		SQL_access_protocol,
		SQL_access_protocol_encrypted,
		NoSQL_access_protocol,
		NoSQL_access_protocol_encrypted,
		BINARY,
		BINARY_encrypted,
		TEXT,
		TEXT_encrypted,
		SSH,
		SSH_tunnel,
		SMTP,
		SMTP_encrypted,
		POP3,
		POP3_encrypted,
		IMAP,
		IMAP_encrypted,
		FTP,
		FTPS,
		SFTP,
		SCP,
		LDAP,
		LDAPS,
		JMS,
		NFS,
		SMB,
		SMB_encrypted,
		LocalFileAccess,
		NRPE,
		XMPP,
		IIOP,
		IIOP_encrypted,
		JRMP,
		JRMP_encrypted,
		InProcessLibraryCall,
		ContainerSpawning,
	}
}

func (what Protocol) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return [...]string{"unknown-protocol", "http", "https", "ws", "wss", "reverse-proxy-web-protocol", "reverse-proxy-web-protocol-encrypted",
		"mqtt", "jdbc", "jdbc-encrypted", "odbc", "odbc-encrypted",
		"sql-access-protocol", "sql-access-protocol-encrypted", "nosql-access-protocol", "nosql-access-protocol-encrypted", "binary", "binary-encrypted", "text", "text-encrypted",
		"ssh", "ssh-tunnel", "smtp", "smtp-encrypted", "pop3", "pop3-encrypted", "imap", "imap-encrypted", "ftp", "ftps", "sftp", "scp", "ldap", "ldaps", "jms", "nfs", "smb", "smb-encrypted", "local-file-access", "nrpe", "xmpp",
		"iiop", "iiop-encrypted", "jrmp", "jrmp-encrypted", "in-process-library-call", "container-spawning"}[what]
}

func (what Protocol) IsProcessLocal() bool {
	return what == InProcessLibraryCall || what == LocalFileAccess || what == ContainerSpawning
}

func (what Protocol) IsEncrypted() bool {
	return what == HTTPS || what == WSS || what == JDBC_encrypted || what == ODBC_encrypted ||
		what == NoSQL_access_protocol_encrypted || what == SQL_access_protocol_encrypted || what == BINARY_encrypted || what == TEXT_encrypted || what == SSH || what == SSH_tunnel ||
		what == FTPS || what == SFTP || what == SCP || what == LDAPS || what == Reverse_proxy_web_protocol_encrypted ||
		what == IIOP_encrypted || what == JRMP_encrypted || what == SMB_encrypted || what == SMTP_encrypted || what == POP3_encrypted || what == IMAP_encrypted
}

func (what Protocol) IsPotentialDatabaseAccessProtocol(includingLaxDatabaseProtocols bool) bool {
	strictlyDatabaseOnlyProtocol := what == JDBC_encrypted || what == ODBC_encrypted ||
		what == NoSQL_access_protocol_encrypted || what == SQL_access_protocol_encrypted || what == JDBC || what == ODBC || what == NoSQL_access_protocol || what == SQL_access_protocol
	if includingLaxDatabaseProtocols {
		// include HTTP for REST-based NoSQL-DBs as well as unknown binary
		return strictlyDatabaseOnlyProtocol || what == HTTPS || what == HTTP || what == BINARY || what == BINARY_encrypted
	}
	return strictlyDatabaseOnlyProtocol
}

func (what Protocol) IsPotentialWebAccessProtocol() bool {
	return what == HTTP || what == HTTPS || what == WS || what == WSS || what == Reverse_proxy_web_protocol || what == Reverse_proxy_web_protocol_encrypted
}
