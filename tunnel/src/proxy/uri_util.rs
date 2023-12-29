
#[test]
fn test() {
    // 示例代理请求字符串
    let proxy_request = "GET http://example.com/path HTTP/1.1\r\nHost: example.com:80\r\n\r\n";
    let connect_request = "CONNECT example.com:443 HTTP/1.1";

    eprintln!("{:?}", resolve_uri(proxy_request.as_bytes()));
    eprintln!("{:?}", resolve_uri(connect_request.as_bytes()));
}

#[derive(PartialEq,Debug)]
pub enum HttpMethod {
    Connect,
    Http,
    Unknown
}

/// 解析Uri
pub fn resolve_uri(header_data: &[u8]) -> (String, String, HttpMethod) {
    if header_data.len() < 8 {
        return ("".to_string(), "".to_string(),HttpMethod::Unknown);
    }
    let prefix = &header_data[0..7];
    return if prefix == b"CONNECT" {
        // eprintln!("connect 请求");
        let mut host_index = 0;
        let mut port_index = 0;
        for index in 8..header_data.len() {
            if header_data[index] == b'\r' {
                break;
            }
            if header_data[index] == b':' {
                host_index = index;
            }
            if header_data[index] == b' ' {
                port_index = index;
                break;
            }
        }
        (String::from_utf8_lossy(&header_data[8..host_index]).to_string(),
         String::from_utf8_lossy(&header_data[host_index + 1..port_index]).to_string(),
         HttpMethod::Connect)
        // eprintln!("host:{}", String::from_utf8_lossy(&header_data[8..host_index]));
        // eprintln!("host:{}", String::from_utf8_lossy(&header_data[host_index + 1..port_index]));
    } else {
        // eprintln!("http 请求");
        let mut host_start_index = 0;
        let mut host_end_index = 0;
        let mut port_start_index = 0;
        let mut port_end_index = 0;
        for index in 0..header_data.len() {
            if header_data[index] == b'\r' {
                break;
            }
            if index > 3 && &header_data[index - 3..index] == b"://" {
                host_start_index = index;
            }
            if host_start_index != 0 && header_data[index] == b':' {
                port_start_index = index + 1;
            }
            if host_start_index != 0 && header_data[index] == b'/' {
                if port_start_index == 0 {
                    host_end_index = index;
                    break;
                } else {
                    host_end_index = port_start_index - 1;
                    port_end_index = index;
                    break;
                }
            }
        }
        (
            String::from_utf8_lossy(&header_data[host_start_index..host_end_index]).to_string(),
            if port_start_index == 0 {
                "80".to_string()
            } else {
                let cow = String::from_utf8_lossy(&header_data[port_start_index..port_end_index]);
                cow.to_string()
            },
            HttpMethod::Http)
        // eprintln!("host:{}", String::from_utf8_lossy(&header_data[host_start_index..host_end_index]));
        // eprintln!("host:{}", if port_start_index == 0 {
        //     "80".to_string()
        // } else {
        //     let cow = String::from_utf8_lossy(&header_data[port_start_index..port_end_index]);
        //     cow.to_string()
        // });
    };
}
