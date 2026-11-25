# Sniffer 2.0

Ứng dụng Windows để bắt và phân tích gói tin mạng, hoặc mở tệp capture có sẵn.

## Lưu ý

Ứng dụng sử dụng .NET 10 và SharpPcap. Để bắt gói tin trực tiếp, cần cài [Npcap](https://npcap.com/#download); quyền truy cập adapter phụ thuộc cấu hình Npcap và quyền của người dùng.

## Hướng dẫn sử dụng

1. Chọn một adapter ở màn hình đầu để bắt gói tin, hoặc chọn **Open capture file** để mở tệp PCAP/PCAPNG mà không cần adapter.
2. Dùng **Start**, **Stop** và **Restart** để điều khiển phiên bắt. **Back** quay về màn hình chọn adapter.
3. Chọn một gói trong danh sách để xem các tầng giao thức và dữ liệu hex/ASCII. Các nút điều hướng chuyển giữa các gói đang hiển thị; **Auto-scroll** tự cuộn đến gói mới.
4. Dùng **File → Open capture** và **File → Save capture** để mở hoặc lưu toàn bộ gói tin. Phần mở rộng `.pcap` hoặc `.pcapng` quyết định định dạng khi lưu.
5. Nhấn **BPF** trên thanh công cụ để mở ô **Capture filter**, rồi nhập bộ lọc trước khi bắt, ví dụ `tcp port 443` hoặc `host 192.0.2.1`. Nút **BPF*** cho biết đã nhập bộ lọc. Bộ lọc chỉ áp dụng cho lần bắt tiếp theo và không áp dụng cho tệp đã mở. Npcap báo lỗi nếu cú pháp không hợp lệ.
6. Nhấn nút tìm kiếm hoặc `Ctrl+F`, nhập nội dung rồi chọn **Next** hoặc nhấn `F3` để tìm trong các gói đang hiển thị. Tìm kiếm không phân biệt chữ hoa/thường, kiểm tra phần tóm tắt và các byte ASCII trong gói; sau gói cuối sẽ quay lại đầu danh sách.
7. **Stats** thống kê các gói đang hiển thị theo giao thức và địa chỉ; **Follow** xem dữ liệu TCP/UDP hai chiều liên quan đến gói được chọn, kể cả các gói bị ẩn bởi bộ lọc hiển thị. **Copy** sao chép tóm tắt; menu Edit cho phép sao chép hex. Menu File có thể xuất gói đang hiển thị thành capture hoặc xuất byte của gói được chọn thành tệp nhị phân.

Phím tắt: `Ctrl+O` mở capture, `Ctrl+S` lưu capture, `Ctrl+F` chuyển đến ô tìm kiếm và `F3` tìm kết quả tiếp theo.

PCAPNG hỗ trợ các khối packet có timestamp và nhiều loại link-layer. Các khối simple packet không có timestamp, độ chính xác dưới nano giây và khối quá 64 MiB hiện không được hỗ trợ; ứng dụng sẽ báo lỗi thay vì bỏ qua. Khi lưu, dữ liệu gói, thời gian, độ dài và loại link-layer được giữ lại, nhưng các metadata/ghi chú khác của PCAPNG không được giữ. Nếu capture có nhiều loại link-layer, hãy lưu dưới dạng PCAPNG.

Danh sách hiển thị số thứ tự, thời gian tương đối, địa chỉ, giao thức, độ dài và thông tin gói. Chọn một gói để xem các tầng và dữ liệu hex/ASCII. Giao diện phân tích Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS và HTTP cơ bản; DNS/HTTP được nhận diện trên dữ liệu từng gói, không ghép lại luồng TCP hay giải mã lưu lượng mã hóa.

Trong vùng dữ liệu, nhấn một byte hexadecimal để tô sáng byte và ký tự ASCII tương ứng. Mỗi dòng chứa tối đa 16 byte; các byte ngoài vùng ASCII in được hiển thị bằng dấu chấm, không phải văn bản đã giải mã từ lưu lượng mã hóa.

Bộ lọc hiển thị hỗ trợ các tên `ip`, `ipv6`, `arp`, `tcp`, `udp`, `icmp`, `icmpv6`, `dns`, `http`, cùng `ip.addr == <địa chỉ>`, `tcp.port == <cổng>`, `udp.port == <cổng>`, toán tử `&&`, `||` và dấu ngoặc. Ví dụ: `udp.port == 53 && ip.addr == 192.0.2.1`. Đây là tập con cú pháp Wireshark; lỗi cú pháp được hiển thị cạnh bộ lọc.

Ô **Display filter** không tìm văn bản tự do: để tìm từ như `online`, dùng **Find** (`Ctrl+F`). Khi biểu thức chưa hợp lệ, thông báo lỗi xuất hiện và bộ lọc hợp lệ trước đó vẫn được giữ.

Các trường bổ sung gồm `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst`, `ipv6.addr`, `tcp.srcport`, `tcp.dstport`, `udp.srcport`, `udp.dstport`, `frame.number` và `frame.len`. Địa chỉ hỗ trợ `==`, `!=`; cổng và các trường frame hỗ trợ `==`, `!=`, `<`, `<=`, `>` và `>=`. Dùng `!` để phủ định một biểu thức, ví dụ `tcp && tcp.dstport == 443 && frame.len > 100`. Với trường `.addr` và `.port`, `!=` chỉ khớp khi cả nguồn lẫn đích đều khác giá trị đã cho; đây không phải toàn bộ ngữ nghĩa bộ lọc của Wireshark.

Theo dõi TCP ghép payload theo số thứ tự riêng từng chiều, loại bỏ phần trùng lặp và đánh dấu khoảng thiếu; một SYN mới được dùng để tách kết nối dùng lại cùng địa chỉ/cổng. Capture thiếu bắt tay hoặc dùng lại endpoint vẫn có thể gây nhập nhằng; không ghép các mảnh IP. UDP được hiển thị theo từng datagram và không phân biệt các phiên dùng lại endpoint. Dữ liệu không in được hiện bằng dấu chấm, lưu lượng mã hóa không được giải mã, và giới hạn phân tích là 16 MiB dữ liệu capture cùng endpoint.

## Giao diện

![Danh sách gói tin, chi tiết giao thức và dữ liệu hex/ASCII](screenshot.png)

*Giao diện phân tích với dữ liệu gói tin giả lập; thanh trạng thái được cắt khỏi ảnh.*

## Yêu cầu

- Windows; .NET 10 Desktop Runtime nếu chạy bản build không tự chứa runtime.
- .NET 10 SDK nếu cần build từ mã nguồn.
- Npcap để bắt gói tin trực tiếp.

Trong VS Code, chọn cấu hình **Sniffer (.NET 10)** và nhấn `F5`; ứng dụng được build Debug tự động trước khi chạy.

Workflow GitHub Actions **Build Windows installer** tạo installer Windows x64 tự chứa .NET và tải lên dưới dạng artifact `Sniffer-Setup-win-x64` khi workflow chạy thành công. Npcap không được đóng gói hoặc tự động cài đặt: sau khi cài, người dùng có thể mở trang Npcap chính thức và tự cài đặt theo giấy phép của Npcap. Mở tệp capture không yêu cầu Npcap.

Để tự động tạo GitHub Release kèm installer, cập nhật `AppVersion` trong `installer\Sniffer.iss` và `AssemblyVersion`/`AssemblyFileVersion` trong `Sniffer\Properties\AssemblyInfo.cs` cho cùng phiên bản, sau đó push tag dạng `vMAJOR.MINOR.PATCH`, ví dụ `v2.0.0`. Workflow chỉ phát hành sau khi kiểm thử, publish và đóng gói thành công; tag phải khớp phiên bản installer và assembly (assembly có thêm `.0`). Release notes được tạo tự động. Nhánh và pull request vẫn chỉ tạo artifact, không phát hành. Nếu release cho tag đã tồn tại hoặc quá trình phát hành lỗi, workflow báo lỗi; có thể còn một release draft cần xử lý thủ công.

## Tải về

Truy cập phiên bản release của ứng dụng tại link này [https://github.com/quocthang0507/Sniffer/releases](https://github.com/quocthang0507/Sniffer/releases)

## Tác giả

Nếu có góp ý cho ứng dụng này, hoặc muốn sử dụng lại, vui lòng liên hệ qua email sau:
La Quốc Thắng - quocthang_0507@yahoo.com.vn