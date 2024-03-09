# Simple Security Header Audit

hdySecurityHeaders is part of a set of personal tools developed to cover robust simple checks and automation that covers areas that are often overlooked or forgotten. More of these such tools will be made public when I feel like it.

**This tool is not intended to be the exclusive means of security header analysis. Rather, its purpose is to assist with performing a straightforward and non-complex audit of current security headers and provide guidance in comparison to recommended industry standard.**

**Disclaimer**:

- This is a personal project for my personal workflow and may/may not receive updates and may/may not work. Who knows. :shrug: 
- Sharing because sharing is caring.
- Always review your local laws regarding use of tools that facilitate penetration testing.

## Description

hdySecurityHeaders is a personal tool to complete a preliminary HTTP scan, and facilitate a manual audit, of active or missing headers for the clients specific environment and tech stack. The tool will perform a check against a map of recommended and provisional headers that improve web applications as well as a map of headers that are insecure, require further attention, or are deprecated and should not be in use.

![image](https://i.imgur.com/3DWHaQi.png)


**Features**

- **OS-agnostic**:  Tool is **OS-agnostic** as the application is built for portability in mind and can be compiled natively for both Windows and Linux platforms.
- **Custom HTTP Headers**: Easily allows for **custom HTTP headers** to provide utility when dealing with unauthenticated and authenticated scanning as well as dealing with edge-cases that require certain headers to successfully interact with the application as intended.
- **Proxy Requests**: **Proxying** to Burp, Zap, or whatever, is simple to easily assist with reviewing configurations and confirming the validity of the findings.
- **Redirects**: Control redirects easily and ensure that your scanning is being completed on the intended page or the subsequent pages that the regular user lands on. Useful when accessing webpages that redirect to a different area immediately.

## Requirements

Dependencies include:

None

## Installation

As always, review code before using public tools. Program is written in golang; you will need Go installed in order to compile. Code is very simple and you can easily adjust to add your own comments, headers, and recommendations you want to keep track of.

```
$ git clone https://github.com/hdysec/hdy-security-headers.git
$ cd hdy-security-headers
$ go build .
```

## Usage

```
Usage:
hdySecurityHeaders -d <domain.com>
hdySecurityHeaders -d <domain.com> -P "http://127.0.0.1:8081"
hdySecurityHeaders -d "subdomain.example.com:8080/service/dashboard.mvc" -H "Cookie: JSESSIONID=qwerqwer_aadsfasdfasdasdfd-Afdfdfp"

Usage:
  hdySecurityHeaders [flags]

Flags:
  -d, --domain string   Provide the URL/Path excluding the protocol (http/s).
  -H, --header string   Provide optional header to include in scanning when doing authenticated scanning.
  -h, --help            help for hdySecurityHeaders
  -P, --proxy string    Provide optional proxy for Burp or Zap interception (http://127.0.0.1:8081)
  -r, --redirect        Instruct tool to follow redirect (Default is to ignore redirects)
```



