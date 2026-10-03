# Reflected XSS Checker (authorized/lab)

Memuat payload dari `All-In-One.txt` dan memeriksa refleksi literal pada respons HTTP.
Tool tidak menjalankan JavaScript atau membuka browser.

```bash
python -m pip install requests
python xss_reflect_scanner.py -c
python xss_reflect_scanner.py -p "http://127.0.0.1:8000/"
python xss_reflect_scanner.py -u "http://127.0.0.1:8000/search?q=test" --mode params -l
python xss_reflect_scanner.py -u "http://127.0.0.1:8000/" --mode no-params -l --lokasi hasil.txt
```

Target remote diblokir default; gunakan localhost/loopback untuk lab.
