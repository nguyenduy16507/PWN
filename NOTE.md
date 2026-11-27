* <img width="558" height="281" alt="image" src="https://github.com/user-attachments/assets/4022b848-2a01-45bd-85fd-d4179db5c8e8" />
* easy:
  - Kĩ thuật khai thác nhanh bằng ID âm và kiểm soát delimiter
  - Kĩ thuật tổng quát để tìm ID đưa con trỏ đến địa chỉ mong muốn : dùng modulo(Đồng dư)
    + `python3 -c 'a=?; b=(?-?)%(1<<64); g=__import__("math").gcd(a,1<<64); print([((b//g)*pow(a//g,-1,(1<<64)//g)+k*((1<<64)//g))%(1<<64) for k in range(g)] if b%g==0 else "Vô nghiệm")'
` :   đây là lệnh tính với thanh ghi 64 bit, với 32b bit thì thay thành 32 
    + Với phép tính : `0x404100+24id≡0x404080` ta dùng lệnh: `python3 -c 'a=24; b=(0x404080-0x404100)%(1<<64); g=__import__("math").gcd(a,1<<64); print([((b//g)*pow(a//g,-1,(1<<64)//g)+k*((1<<64)//g))%(1<<64) for k in range(g)] if b%g==0 else "Vô nghiệm")' để tính ra được id `
    + Thông thường ta sẽ chỉ dùng nghiệm nhỏ nhất để phù hợp với cả biến có dấu lẫn ko dấu. Thêm `min` vào.
    + <img width="620" height="27" alt="image" src="https://github.com/user-attachments/assets/74e493ff-ef96-45ae-924d-1b89cbcd7fc7" />

