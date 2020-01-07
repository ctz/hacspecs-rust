#[derive(Debug, Copy, Clone)]
pub struct ProtocolOptions {
    resuming: bool,
    request_client_auth: bool,
    perform_client_auth: bool,
    dh_anon: bool,
    rsa_kem: bool,
    server_issues_ticket: bool,
}

impl Default for ProtocolOptions {
    fn default() -> Self {
        ProtocolOptions {
            resuming: false,
            request_client_auth: false,
            perform_client_auth: false,
            dh_anon: false,
            rsa_kem: false,
            server_issues_ticket: false,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MessageType {
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    ClientKeyExchange,
    CertificateVerify,
    NewSessionTicket,
    ChangeCipherSpec,
    Finished,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Peer {
    Server,
    Client,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum State {
    ClientSendsClientHello,
    ServerSendsServerHello,
    ServerSendsCertificate,
    ServerSendsServerKeyExchange,
    ServerSendsCertificateRequest,
    ServerSendsServerHelloDone,
    ClientSendsCertificate,
    ClientSendsClientKeyExchange,
    ClientSendsCertificateVerify,
    ClientSendsChangeCipherSpec,
    ClientSendsFinished,
    ServerSendsNewSessionTicket,
    ServerSendsChangeCipherSpec,
    ServerSendsFinished,
    Term,
}

impl Default for State {
    fn default() -> Self { State::ClientSendsClientHello }
}

impl State {
    pub fn sends(self) -> (Peer, MessageType) {
        use State::*;
        match self {
            ClientSendsClientHello => (Peer::Client, MessageType::ClientHello),
            ServerSendsServerHello => (Peer::Server, MessageType::ServerHello),
            ServerSendsCertificate => (Peer::Server, MessageType::Certificate),
            ServerSendsServerKeyExchange => (Peer::Server, MessageType::ServerKeyExchange),
            ServerSendsCertificateRequest => (Peer::Server, MessageType::CertificateRequest),
            ServerSendsServerHelloDone => (Peer::Server, MessageType::ServerHelloDone),
            ClientSendsCertificate => (Peer::Client, MessageType::Certificate),
            ClientSendsClientKeyExchange => (Peer::Client, MessageType::ClientKeyExchange),
            ClientSendsCertificateVerify => (Peer::Client, MessageType::CertificateVerify),
            ClientSendsChangeCipherSpec => (Peer::Client, MessageType::ChangeCipherSpec),
            ClientSendsFinished => (Peer::Client, MessageType::Finished),
            ServerSendsNewSessionTicket => (Peer::Server, MessageType::NewSessionTicket),
            ServerSendsChangeCipherSpec => (Peer::Server, MessageType::ChangeCipherSpec),
            ServerSendsFinished => (Peer::Server, MessageType::Finished),
            Term => panic!(),
        }
    }
}

pub fn step(st: State, opts: ProtocolOptions) -> State {
    use State::*;

    match st {
        ClientSendsClientHello => ServerSendsServerHello,
        ServerSendsServerHello => {
            if opts.resuming {
                if opts.server_issues_ticket {
                    ServerSendsNewSessionTicket
                } else {
                    ServerSendsFinished
                }
            } else {
                if opts.dh_anon {
                    ServerSendsServerKeyExchange
                } else {
                    ServerSendsCertificate
                }
            }
        }
        ServerSendsCertificate => {
            if opts.rsa_kem {
                if opts.request_client_auth {
                    ServerSendsCertificateRequest
                } else {
                    ServerSendsServerHelloDone
                }
            } else {
                ServerSendsServerKeyExchange
            }
        }
        ServerSendsServerKeyExchange => {
            if opts.request_client_auth {
                ServerSendsCertificateRequest
            } else {
                ServerSendsServerHelloDone
            }
        }
        ServerSendsCertificateRequest => ServerSendsServerHelloDone,
        ServerSendsServerHelloDone => {
            if opts.request_client_auth {
                ClientSendsCertificate
            } else {
                ClientSendsClientKeyExchange
            }
        }
        ClientSendsCertificate => ClientSendsClientKeyExchange,
        ClientSendsClientKeyExchange => {
            if opts.perform_client_auth {
                ClientSendsCertificateVerify
            } else {
                ClientSendsChangeCipherSpec
            }
        }
        ClientSendsCertificateVerify => ClientSendsChangeCipherSpec,
        ClientSendsChangeCipherSpec => ClientSendsFinished,
        ClientSendsFinished => {
            if opts.resuming {
                Term
            } else {
                if opts.server_issues_ticket {
                    ServerSendsNewSessionTicket
                } else {
                    ServerSendsChangeCipherSpec
                }
            }
        }
        ServerSendsNewSessionTicket => ServerSendsChangeCipherSpec,
        ServerSendsChangeCipherSpec => ServerSendsFinished,
        ServerSendsFinished => {
            if opts.resuming {
                ClientSendsChangeCipherSpec
            } else {
                Term
            }
        }
        Term => Term,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn print(opts: ProtocolOptions) {
        let mut state = State::default();
        loop {
            let send = state.sends();
            println!("{:?} sends {:?}", send.0, send.1);
            let next = step(state, opts);
            //println!("{:?} -> {:?}", state, next);
            if next == State::Term {
                break;
            }
            state = next;
        }
    }

    #[test]
    fn resume() {
        print(ProtocolOptions { resuming: true, ..Default::default() });
    }

    #[test]
    fn full() {
        print(ProtocolOptions::default());
    }

    #[test]
    fn request_client_auth() {
        print(ProtocolOptions { request_client_auth: true, ..Default::default() });
    }

    #[test]
    fn perform_client_auth() {
        print(ProtocolOptions {
            request_client_auth: true,
            perform_client_auth: true,
            ..Default::default()
        });
    }

    #[test]
    fn resumes_and_issues_ticket() {
        print(ProtocolOptions {
            resuming: true,
            server_issues_ticket: true,
            ..Default::default()
        });
    }

    fn linearise(opts: ProtocolOptions) {
        let mut state = State::default();
        let mut v = Vec::new();
        loop {
            let send = state.sends();
            v.push((state, send.0, send.1));
            let next = step(state, opts);
            if next == State::Term {
                break;
            }
            state = next;
        }

        for (st, peer, msg) in v {
            print!("{:?} < ", st);
        }
        println!("");
    }

    #[test]
    fn rustls_subset() {
        for resume in &[ true, false ] {
            for ticket in &[ true, false ] {
                for (req_client_auth, do_client_auth) in &[ (false, false), (true, false), (true, true) ] {
                    let opts = ProtocolOptions {
                        resuming: *resume,
                        server_issues_ticket: *ticket,
                        request_client_auth: *req_client_auth,
                        perform_client_auth: *do_client_auth,
                        ..Default::default()
                    };
                    linearise(opts);
                }
            }
        }
    }
}
