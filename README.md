# 🔥 ssrf-king 🔥
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
### v1.12 Latest
SSRF plugin for burp that Automates SSRF Detection in all of the Request

![alt text](https://image.flaticon.com/icons/png/128/1320/1320457.png)


**If you are facing any problems or would like a new feature that is not listed below**
**Please create a new issue below in this form**

**[Create New Issue](https://github.com/ethicalhackingplayground/ssrf-king/issues/new)**

### Upcoming Features Checklist
* ✔️ It will soon have a user Interface to specifiy your own call back payload 
* It will soon be able to test Json & XML
* Test for SMTP SSRF

### How to Install/Build
* ``` git clone https://github.com/ethicalhackingplayground/ssrf-king ```
* ``` gradle build ```
* Now the file "ssrf-king.jar" could be found under build/libs which can then be imported Burpsuite. 
* Alternatively, goto [releases](https://github.com/ethicalhackingplayground/ssrf-king/releases) to download the compiled file.

### Features

* ✔️ Test all of the request for any external interactions.
* ✔️ Checks to see if any interactions are not the users IP if it is, it's an open redirect.
* ✔️ Alerts the user for any external interactions with information such as:
  - Endpoint Vulnerable
  - Host
  - Location Found
  
It also performs the following tests based on this research:

**Reference:**

https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

```http
GET http://burpcollab/some/endpoint HTTP/1.1
Host: example.com
...
```
and
```http
GET @burpcollab/some/endpoint HTTP/1.1
Host: example.com
...
```
and
```http
GET /some/endpoint HTTP/1.1
Host: example.com:80@burpcollab
...
```
and
```http
GET /some/endpoint HTTP/1.1
Host: burpcollab
...
```
and
```http
GET /some/endpoint HTTP/1.1
Host: example.com
X-Forwarded-Host: burpcollab
...
```

### Contributors
<a href="https://github.com/ethicalhackingplayground/ssrf-king/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ethicalhackingplayground/ssrf-king" />
</a>


### Scanning Options

* ✔️ Supports Both Passive & Active Scanning.

### Example

* Load the website you want to test.

![GitHub Logo](Pictures/ss-1.PNG)

* Add it as an inscope host in burp.

![GitHub Logo](Pictures/ss-2.PNG)

* Load the plugin.

![GitHub Logo](Pictures/ss-3.PNG)

* Keep note of the Burp Collab Payload.

![GitHub Logo](Pictures/ss-4.PNG)

* Passively crawl the page, ssrf-king test everything in the request on the fly.

![GitHub Logo](Pictures/ssf-5.PNG)

* When it finds a vulnerabilitiy it logs the information and adds an alert.

![GitHub Logo](Pictures/ssrf-6.PNG)


**From here onwards you would fuzz the parameter to test for SSRF.**

![GitHub Logo](Pictures/ssrf-7.PNG)


### Video Demonstration

[![Watch the video](https://i.imgur.com/cYD6gfE.png)](https://www.youtube.com/watch?v=oIkPpgqKfsg)

**If you get a bounty please support by buying me a coffee**

<br>
<a href="https://www.buymeacoffee.com/krypt0mux" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>
