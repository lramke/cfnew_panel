var Wt=[7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21],_e=new Uint32Array(64);for(let p=0;p<64;p++)_e[p]=Math.floor(Math.abs(Math.sin(p+1))*2**32);function Vt(p){let m=p.length,f=m*8,n=(m+8>>6)+1<<6,E=new Uint8Array(n);E.set(p),E[m]=128;let S=new DataView(E.buffer);S.setUint32(n-8,f>>>0,!0),S.setUint32(n-4,Math.floor(f/2**32),!0);let H=1732584193,R=4023233417,K=2562383102,D=271733878,T=new Uint32Array(16);for(let q=0;q<n;q+=64){for(let N=0;N<16;N++)T[N]=S.getUint32(q+N*4,!0);let I=H,C=R,k=K,U=D;for(let N=0;N<64;N++){let A,z;N<16?(A=C&k|~C&U,z=N):N<32?(A=U&C|~U&k,z=(5*N+1)%16):N<48?(A=C^k^U,z=(3*N+5)%16):(A=k^(C|~U),z=7*N%16),A=A+I+_e[N]+T[z]>>>0,I=U,U=k,k=C;let G=Wt[N];C=C+(A<<G|A>>>32-G)>>>0}H=H+I>>>0,R=R+C>>>0,K=K+k>>>0,D=D+U>>>0}let B=new DataView(new ArrayBuffer(16));return B.setUint32(0,H,!0),B.setUint32(4,R,!0),B.setUint32(8,K,!0),B.setUint32(12,D,!0),[...new Uint8Array(B.buffer)].map(q=>q.toString(16).padStart(2,"0")).join("")}function Qe(p){if(p!=="md5")throw new Error("浏览器构建仅支持 md5");let m="";return{update(f){return m+=String(f),this},digest(f){let n=Vt(new TextEncoder().encode(m));return n}}}var Xt=/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;function le(p){let m=String(p??"");if(Xt.test(m))return 4;if(!m.includes(":"))return 0;try{return new URL("http://["+m+"]/").hostname.startsWith("[")?6:0}catch{return 0}}function et(){return new Uint8Array(0)}function tt(){let p=globalThis.__CFNEW_RULES_TEXT__;if(!p)throw new Error("分流规则尚未加载，请稍后重试");return p}var me="♻️ 自动选择",nt=["🌍 国外媒体","📲 电报信息","🌐 谷歌服务","🤖 OpenAI","Ⓜ️ 微软服务","🍎 苹果服务","📺 哔哩哔哩","📹 油管视频","🎬 奈飞视频","🎯 全球直连","🐟 漏网之鱼"],_t=["select","direct",me,"🚀 节点选择","🛑 全球拦截","🍃 应用净化",...nt],ue;function Qt(){if(!ue){ue=JSON.parse(tt(et(new URL("./singbox-rules.json.gz",import.meta.url))));let p=m=>{for(let f of Object.values(m))f&&typeof f=="object"&&p(f);Object.freeze(m)};p(ue.rules)}return Object.entries(ue.rules).map(([p,m])=>({type:"inline",tag:p,rules:m}))}function ke(p){let m=new Set(_t);return p.map(f=>{let n=String(f.name||f.server+":"+f.port),E=n;for(let S=2;m.has(E);S++)E=n+" "+S;return m.add(E),{...f,name:E}})}function pe(p){return String(p||"").replace(/^\[|\]$/g,"")}function en(p){let m={type:p.proto,tag:p.name,server:pe(p.server),server_port:p.port};return p.proto==="vless"?(m.uuid=p.uuid,p.flow&&(m.flow=p.flow)):m.password=p.password,p.tls&&!(p.proto==="trojan"&&p.security==="none")&&(m.tls={enabled:!0,server_name:pe(p.sni||p.host||p.server),insecure:!1,utls:{enabled:!0,fingerprint:p.fp||"chrome"}},p.alpn?.length&&(m.tls.alpn=[...p.alpn]),p.ech&&(m.tls.ech={enabled:!0})),p.network==="ws"||p.network==="xhttp"?m.transport={type:"ws",path:p.path||"/",headers:{Host:pe(p.host||p.server)},max_early_data:2048,early_data_header_name:"Sec-WebSocket-Protocol"}:p.network==="grpc"&&(m.transport={type:"grpc",service_name:p.path||""}),m}function tn(p){let m=String(p||"https://223.5.5.5/dns-query").trim(),f=new URL(m.includes("://")?m:"udp://"+(le(m)===6?"["+m+"]":m));if(f.protocol==="quic:")throw new Error("这条Worker链路不能转发QUIC DNS，请改用HTTPS、TLS或TCP地址。");let E={"https:":"https","tls:":"tls","tcp:":"tcp","udp:":"tcp","http3:":"https","h3:":"https"}[f.protocol];if(!E||!f.hostname||f.username||f.password)throw new Error("DNS地址格式无效");let S={type:E,tag:"remote",server:pe(f.hostname),detour:"select"};return f.port&&(S.server_port=Number(f.port)),E==="https"&&(S.path=(f.pathname==="/"?"/dns-query":f.pathname)+f.search),S}function ot(p,m={}){let f=ke(p.filter(T=>T&&["vless","trojan"].includes(T.proto))),n=f.map(T=>T.name),E=tn(m.dns),S=[...new Set([...f.flatMap(T=>[T.server,T.sni,T.host]),E.server].map(pe).filter(T=>T&&!le(T)))],H=n.length?me:"direct",R=n.length?[me,...n,"direct"]:["direct"],K=nt.map(T=>({type:"selector",tag:T,outbounds:T==="🎯 全球直连"?["direct"]:["select",...n,"direct"],default:["Ⓜ️ 微软服务","🍎 苹果服务","📺 哔哩哔哩","🎯 全球直连"].includes(T)?"direct":"select"})),D=(T,B)=>({rule_set:T,outbound:B});return{log:{level:"info",timestamp:!0},dns:{servers:[{type:"local",tag:"local"},E,{type:"fakeip",tag:"fakeip",inet4_range:"198.18.0.0/15",inet6_range:"fc00::/18"}],rules:[...S.length?[{domain:S,server:"local"}]:[],{rule_set:"geosite-category-ads-all",action:"reject"},{rule_set:["geosite-cn","geosite-private"],server:"local"},{query_type:["A","AAAA"],server:"fakeip"}],final:"remote"},inbounds:[{type:"mixed",tag:"mixed-in",listen:"127.0.0.1",listen_port:2080},{type:"tun",tag:"tun-in",interface_name:"sing-box",address:["172.19.0.1/30","fdfe:dcba:9876::1/126"],mtu:1500,auto_route:!0,strict_route:!0,stack:"mixed"}],outbounds:[{type:"selector",tag:"select",outbounds:R,default:H},...n.length?[{type:"urltest",tag:me,outbounds:n,url:"https://www.gstatic.com/generate_204",interval:"5m",tolerance:50,idle_timeout:"30m",interrupt_exist_connections:!1}]:[],...K,...f.map(en),{type:"direct",tag:"direct"}],route:{rule_set:Qt(),rules:[{action:"sniff"},{protocol:"dns",action:"hijack-dns"},{ip_is_private:!0,outbound:"direct"},{rule_set:"geosite-category-ads-all",action:"reject"},{network:"udp",port:443,action:"reject"},D("geosite-private","direct"),D("geosite-apple-cn","direct"),D("geosite-microsoft@cn","direct"),D("geosite-apple","🍎 苹果服务"),D("geosite-microsoft","Ⓜ️ 微软服务"),D(["geosite-openai","geosite-anthropic"],"🤖 OpenAI"),D(["geosite-telegram","geoip-telegram"],"📲 电报信息"),D("geosite-google","🌐 谷歌服务"),D("geosite-youtube","📹 油管视频"),D("geosite-netflix","🎬 奈飞视频"),D(["geosite-disney","geosite-spotify","geosite-tiktok","geosite-twitter","geosite-facebook"],"🌍 国外媒体"),D(["geosite-github","geosite-geolocation-!cn"],"select"),D(["geosite-cn","geoip-cn"],"direct")],final:"🐟 漏网之鱼",default_domain_resolver:{server:"local",strategy:"prefer_ipv4"},auto_detect_interface:!0},experimental:{cache_file:{enabled:!0,store_fakeip:!0},clash_api:{external_controller:"127.0.0.1:9090"}}}}function rt(p,m){let f=new TextDecoder;function n(t){let e=atob(t),o=new Uint8Array(e.length);for(let s=0;s<e.length;s++)o[s]=e.charCodeAt(s);return f.decode(o)}let E="351c9981-04b6-4103-aa4b-864aa9c91469",S="",H="",R=[],K=[],D=!1,T=!1,B=!1,q=!1,I=!0,C="",k="",U="",N="",A=!0,z=!1,G=!1,W="",F=!1,j="https://223.5.5.5/dns-query",V="cloudflare-ech.com",X="",Ne=n("aHR0cHM6Ly91cmwudjEubWsvc3Vi"),ct="https://raw.githubusercontent.com/byJoey/test/refs/heads/main/tist.ini",fe=!0,ge=!0,Ye=!0,$e=!1,he=!1,de={},Te=Object.hasOwn(p,"freeCpu"),ne={freeCpu:"no",wk:"",ev:"yes",et:"no",ex:"no",ech:"no",tp:"",customDNS:"https://223.5.5.5/dns-query",customECHDomain:"cloudflare-ech.com",alpn:"",d:"",p:"",yx:"",yxURL:"",s:"",homepage:"",scu:n("aHR0cHM6Ly91cmwudjEubWsvc3Vi"),ena:"no",epd:"yes",epi:"yes",egi:"yes",ae:"",rm:"",qj:"",dkby:"no",yxby:"",ipv4:"yes",ipv6:"yes",ispMobile:"yes",ispUnicom:"yes",ispTelecom:"yes",jk:"no"};function Ue(t,e=!1){if(t==null||t==="")return e;if(t===!0||t===!1)return t;let o=String(t).trim().toLowerCase();return o==="yes"||o==="true"||o==="1"||o==="on"?!0:o==="no"||o==="false"||o==="0"||o==="off"?!1:e}function lt(t,e=!1){return Ue(t,e)?"yes":"no"}function pt(t){let e={...ne,...t};return["freeCpu","ev","et","ex","ech","ena","epd","epi","egi","ipv4","ipv6","ispMobile","ispUnicom","ispTelecom","jk"].forEach(o=>{e[o]=lt(e[o],Ue(ne[o]))}),e.ev==="no"&&e.et==="no"&&e.ex==="no"&&(e.ev="yes"),e.ech==="yes"&&(e.dkby="yes"),e}function dt(t,...e){if(t){for(let o of e)if(t[o]!==void 0&&t[o]!==null&&t[o]!=="")return t[o]}}function ut(t={}){let e={freeCpu:["freeCpu","FREE_CPU"],wk:["wk","WK"],ev:["ev","EV"],et:["et","ET"],ex:["ex","EX"],ech:["ech","ECH"],tp:["tp","TP"],customDNS:["customDNS","CUSTOMDNS","CUSTOM_DNS"],customECHDomain:["customECHDomain","CUSTOMECHDOMAIN","CUSTOM_ECH_DOMAIN"],alpn:["alpn","ALPN"],d:["d","D"],p:["p","P"],yx:["yx","YX"],yxURL:["yxURL","YXURL","YX_URL"],s:["s","S"],homepage:["homepage","HOMEPAGE"],scu:["scu","SCU"],ena:["ena","ENA"],epd:["epd","EPD"],epi:["epi","EPI"],egi:["egi","EGI"],ae:["ae","AE"],rm:["rm","RM"],qj:["qj","QJ"],dkby:["dkby","DKBY"],yxby:["yxby","YXBY"],ipv4:["ipv4","IPV4"],ipv6:["ipv6","IPV6"],ispMobile:["ispMobile","ISPMOBILE","ISP_MOBILE"],ispUnicom:["ispUnicom","ISPUNICOM","ISP_UNICOM"],ispTelecom:["ispTelecom","ISPTELECOM","ISP_TELECOM"],jk:["jk","JK"]},o={};for(let[s,i]of Object.entries(e)){let a=dt(t,...i);a!==void 0&&(o[s]=a)}return o}function mt(t={}){return pt({...ut(t),...de})}let Pe=["pp.xy.kg"];function He(){return{domain:Pe[Math.floor(Math.random()*Pe.length)],region:"CF",regionCode:"CF",port:443}}let Me=[{domain:n("UHJveHlJUC5ISy5DTUxpdXNzc3MubmV0"),region:"HK",regionCode:"HK",port:443},{domain:n("UHJveHlJUC5VUy5DTUxpdXNzc3MubmV0"),region:"US",regionCode:"US",port:443},{domain:n("UHJveHlJUC5TRy5DTUxpdXNzc3MubmV0"),region:"SG",regionCode:"SG",port:443},{domain:n("UHJveHlJUC5KUC5DTUxpdXNzc3MubmV0"),region:"JP",regionCode:"JP",port:443},{domain:n("UHJveHlJUC5LUi5DTUxpdXNzc3MubmV0"),region:"KR",regionCode:"KR",port:443},{domain:n("UHJveHlJUC5ERS5DTUxpdXNzc3MubmV0"),region:"DE",regionCode:"DE",port:443},{domain:n("UHJveHlJUC5TRS5DTUxpdXNzc3MubmV0"),region:"SE",regionCode:"SE",port:443},{domain:n("UHJveHlJUC5OTC5DTUxpdXNzc3MubmV0"),region:"NL",regionCode:"NL",port:443},{domain:n("UHJveHlJUC5GSS5DTUxpdXNzc3MubmV0"),region:"FI",regionCode:"FI",port:443},{domain:n("UHJveHlJUC5HQi5DTUxpdXNzc3MubmV0"),region:"GB",regionCode:"GB",port:443},{domain:n("UHJveHlJUC5PcmFjbGUuY21saXVzc3NzLm5ldA=="),region:"Oracle",regionCode:"Oracle",port:443},{domain:n("UHJveHlJUC5EaWdpdGFsT2NlYW4uQ01MaXVzc3NzLm5ldA=="),region:"DigitalOcean",regionCode:"DigitalOcean",port:443},{domain:n("UHJveHlJUC5WdWx0ci5DTUxpdXNzc3MubmV0"),region:"Vultr",regionCode:"Vultr",port:443},{domain:n("UHJveHlJUC5NdWx0YWNvbS5DTUxpdXNzc3MubmV0"),region:"Multacom",regionCode:"Multacom",port:443}],ft=[{name:"cloudflare.182682.xyz",domain:"cloudflare.182682.xyz"},{name:"speed.marisalnc.com",domain:"speed.marisalnc.com"},{domain:"freeyx.cloudflare88.eu.org"},{domain:"bestcf.top"},{domain:"cdn.2020111.xyz"},{domain:"cfip.cfcdn.vip"},{domain:"cf.0sm.com"},{domain:"cf.090227.xyz"},{domain:"cf.zhetengsha.eu.org"},{domain:"cloudflare.9jy.cc"},{domain:"cf.zerone-cdn.pp.ua"},{domain:"cfip.1323123.xyz"},{domain:"cnamefuckxxs.yuchen.icu"},{domain:"cloudflare-ip.mofashi.ltd"},{domain:"115155.xyz"},{domain:"cname.xirancdn.us"},{domain:"f3058171cad.002404.xyz"},{domain:"8.889288.xyz"},{domain:"cdn.tzpro.xyz"},{domain:"cf.877771.xyz"},{domain:"xn--b6gac.eu.org"}],ae=atob("SW52YWxpZCBTT0NLUyBhZGRyZXNzIGZvcm1hdA=="),Re=atob("c29ja3M1Oi8v"),De=atob("c29ja3M6Ly8="),Ae=atob("aHR0cDovLw=="),Fe=atob("aHR0cHM6Ly8="),je="p5",gt="pt",Ke="pts",Be={},ye=!1;function Oe(t){return le(t)!==0}function be(t){return String(t||"").trim().replace(/^\[([^\]]+)\]$/,"$1")}function ve(t,e="Node"){let o=String(t||"").trim();return(!o||/^自定义优选-/i.test(o))&&(o=e),o=o.replace(/^\[([^\]]+)\]$/,"$1").replace(/^https?:\/\//i,"").replace(/[/?#].*$/,"").replace(/\s+/g,"_"),o||e}function ht(t){let e=be(t?.ip||t?.domain||"");if(e&&e.includes(":")&&/^[0-9a-fA-F:.]+$/.test(e))return ve(t?.isp||t?.name||"","IPv6优选");if(e&&!Oe(e))return"优选域名";let o=ve(t?.isp||t?.name||"","IPv4优选"),s=ve(t?.colo||"","");return s?`${o}-${s}`:o}function oe(t=!1){let e={};return o=>{let s=ht(o);return t?s:(e[s]=(e[s]||0)+1,`${s}-${String(e[s]).padStart(2,"0")}`)}}function ze(t){let e=["","h3","h2","http/1.1","h3,h2","h2,http/1.1","h3,h2,http/1.1"],o=String(t||"").trim();return e.includes(o)?o:""}function Ze(t){let e=ze(X);e&&t.set("alpn",e)}function J(t,e=""){return de[t]!==void 0?de[t]:e}async function xe(t="",e=I){if(!t||t==="CF"||Me.length===0)return He();let o=Me.map(i=>({...i,available:!0}));if(e&&t){let i=vt(t,o,e);if(i.length>0)return i[0]}return o[0]}function yt(t){return{US:["SG","JP","KR"],SG:["JP","KR","US"],JP:["SG","KR","US"],KR:["JP","SG","US"],DE:["NL","GB","SE","FI"],SE:["DE","NL","FI","GB"],NL:["DE","GB","SE","FI"],FI:["SE","DE","NL","GB"],GB:["DE","NL","SE","FI"]}[t]||[]}function bt(t){let e=yt(t),o=["US","SG","JP","KR","DE","SE","NL","FI","GB"];return[t,...e,...o.filter(s=>s!==t&&!e.includes(s))]}function vt(t,e,o=I){if(!o||!t)return e;let s=bt(t),i=[];for(let a of s){let c=e.filter(g=>g.regionCode===a);i.push(...c)}return i}function xt(t){if(t.includes("[")&&t.includes("]")){let o=t.match(/^\[([^\]]+)\](?::(\d+))?$/);if(o)return{address:o[1],port:o[2]?parseInt(o[2],10):null}}let e=t.lastIndexOf(":");if(e>0){let o=t.substring(0,e),s=t.substring(e+1),i=parseInt(s,10);if(!o.includes(":")&&!isNaN(i)&&i>0&&i<=65535)return{address:o,port:i}}return{address:t,port:null}}function Z(t){return t==null?'""':'"'+String(t).replace(/\\/g,"\\\\").replace(/"/g,'\\"')+'"'}function Q(t){if(!t)return t;let e=String(t);return e.startsWith("[")&&e.endsWith("]")?e.slice(1,-1):e}function _(t,e={}){let{directFirst:o=!1,extraGroups:s=[]}=e,i=t.length?t.map(c=>`      - ${Z(c)}`).join(`
`):"      - DIRECT",a=[];o?a.push('      - "🎯 全球直连"','      - "🚀 节点选择"'):a.push('      - "🚀 节点选择"','      - "🎯 全球直连"');for(let c of s)a.push(`      - ${Z(c)}`);return a.push(i),a.join(`
`)}function P(t,e={}){let{directFirst:o=!1,extraGroups:s=[],compact:i=!1}=e,a=i?",":", ",c=t.length?t.join(a):"DIRECT",g=[];return o?g.push("🎯 全球直连","🚀 节点选择"):g.push("🚀 节点选择","🎯 全球直连"),g.push(...s),t.length&&g.push(c),g.join(a)}function re(t){try{if(t.startsWith(n("dmxlc3M6Ly8="))){let e=new URL(t),o=new URLSearchParams(e.search);return{proto:n("dmxlc3M="),name:decodeURIComponent(e.hash.substring(1))||e.hostname+":"+e.port,uuid:e.username,server:Q(e.hostname),port:parseInt(e.port)||443,tls:o.get("security")==="tls"||o.get("security")===n("cmVhbGl0eQ=="),network:o.get("type")||"ws",path:o.get("path")||"/?ed=2048",host:Q(o.get("host")||e.hostname),sni:Q(o.get("sni")||o.get("host")||e.hostname),alpn:(o.get("alpn")||"").split(",").map(s=>s.trim()).filter(Boolean),fp:o.get("fp")||"chrome",flow:o.get("flow")||"",encryption:o.get("encryption")||"none",mode:o.get("mode")||"",ech:o.get("ech")||""}}if(t.startsWith(n("dHJvamFuOi8v"))){let e=new URL(t),o=new URLSearchParams(e.search);return{proto:n("dHJvamFu"),name:decodeURIComponent(e.hash.substring(1))||e.hostname+":"+e.port,password:decodeURIComponent(e.username),security:o.get("security")||"tls",server:Q(e.hostname),port:parseInt(e.port)||443,tls:!0,network:o.get("type")||"ws",path:o.get("path")||"/?ed=2048",host:Q(o.get("host")||e.hostname),sni:Q(o.get("sni")||o.get("host")||e.hostname),alpn:(o.get("alpn")||"").split(",").map(s=>s.trim()).filter(Boolean),fp:o.get("fp")||"chrome",ech:o.get("ech")||""}}}catch{}return null}function qe(t){let e=[],o=Q(t.server),s=Q(t.host)||o,i=Q(t.sni)||s;if(e.push(`  - name: ${Z(t.name)}`),e.push(`    type: ${t.proto}`),e.push(`    server: ${Z(o)}`),e.push(`    port: ${t.port}`),t.proto===n("dmxlc3M=")?(e.push(`    uuid: ${t.uuid}`),e.push("    udp: true"),e.push(`    tls: ${t.tls?"true":"false"}`),t.flow&&e.push(`    flow: ${Z(t.flow)}`),e.push(`    client-fingerprint: ${Z(t.fp||"chrome")}`)):t.proto===n("dHJvamFu")&&(e.push(`    password: ${Z(t.password)}`),e.push("    udp: true"),e.push(`    client-fingerprint: ${Z(t.fp||"chrome")}`)),t.tls&&(e.push(`    servername: ${Z(i)}`),t.alpn&&t.alpn.length&&e.push(`    alpn: [${t.alpn.map(a=>Z(a)).join(", ")}]`),e.push("    skip-cert-verify: false")),t.network==="ws"||t.network==="xhttp"?(e.push("    network: ws"),e.push("    ws-opts:"),e.push(`      path: ${Z(t.path)}`),e.push("      headers:"),e.push(`        Host: ${Z(s)}`)):t.network==="grpc"&&(e.push("    network: grpc"),e.push("    grpc-opts:"),e.push(`      grpc-service-name: ${Z(t.path)}`)),t.ech){let a=V||"cloudflare-ech.com";e.push("    ech-opts:"),e.push("      enable: true"),e.push(`      query-server-name: ${Z(a)}`)}return e.join(`
`)}function It(t,e={}){let o=ke(t.map(re).filter(b=>b&&(b.proto===n("dmxlc3M=")||b.proto===n("dHJvamFu")))),s=o.map(b=>b.name),a=["mixed-port: 7890","allow-lan: true","mode: rule","log-level: info","ipv6: true","external-controller: 127.0.0.1:9090","unified-delay: true","tcp-concurrent: true","geodata-mode: true","geo-auto-update: true","geo-update-interval: 24","geox-url:",'  geoip: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"','  geosite: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"','  mmdb: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"','  asn: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"',"sniffer:","  enable: true","  force-dns-mapping: true","  parse-pure-ip: true","  sniff:","    HTTP:","      ports: [80, 8080-8880]","      override-destination: true","    TLS:","      ports: [443, 8443]","    QUIC:","      ports: [443, 8443]","dns:","  enable: true","  listen: 0.0.0.0:1053","  ipv6: true","  enhanced-mode: fake-ip","  fake-ip-range: 198.18.0.1/16","  fake-ip-filter:",'    - "*.lan"','    - "+.local"','    - "+.market.xiaomi.com"','    - "+.msftconnecttest.com"','    - "+.msftncsi.com"','    - "localhost.ptlogin2.qq.com"','    - "+.srv.nintendo.net"','    - "+.stun.playstation.net"','    - "+.xboxlive.com"',"  default-nameserver:","    - 223.5.5.5","    - 119.29.29.29","  nameserver:",`    - ${j||"https://223.5.5.5/dns-query"}`,"    - https://119.29.29.29/dns-query","  fallback:","    - https://1.1.1.1/dns-query","    - https://8.8.8.8/dns-query","  fallback-filter:","    geoip: true","    geoip-code: CN","    ipcidr:","      - 240.0.0.0/4",""],c=["proxies:"];for(let b of o)c.push(qe(b));let g=s.length?s.map(b=>`      - ${Z(b)}`).join(`
`):"      - DIRECT",r=[n("cHJveHktZ3JvdXBzOg=="),'  - name: "🚀 节点选择"',"    type: select","    proxies:",'      - "♻️ 自动选择"','      - "🎯 全球直连"',g,'  - name: "♻️ 自动选择"',"    type: url-test","    url: https://www.gstatic.com/generate_204","    interval: 300","    tolerance: 50","    lazy: true","    proxies:",g,'  - name: "🌍 国外媒体"',"    type: select","    proxies:",_(s),'  - name: "📺 哔哩哔哩"',"    type: select","    proxies:",_(s,{directFirst:!0}),'  - name: "📹 油管视频"',"    type: select","    proxies:",_(s,{extraGroups:["🌍 国外媒体"]}),'  - name: "🎬 奈飞视频"',"    type: select","    proxies:",_(s,{extraGroups:["🌍 国外媒体"]}),'  - name: "📲 电报信息"',"    type: select","    proxies:",_(s),'  - name: "🌐 谷歌服务"',"    type: select","    proxies:",_(s),'  - name: "🤖 OpenAI"',"    type: select","    proxies:",_(s),'  - name: "Ⓜ️ 微软服务"',"    type: select","    proxies:",_(s,{directFirst:!0}),'  - name: "🍎 苹果服务"',"    type: select","    proxies:",_(s,{directFirst:!0}),'  - name: "🎯 全球直连"',"    type: select","    proxies:","      - DIRECT",'  - name: "🛑 全球拦截"',"    type: select","    proxies:","      - REJECT","      - DIRECT",'  - name: "🍃 应用净化"',"    type: select","    proxies:","      - REJECT","      - DIRECT",'  - name: "🐟 漏网之鱼"',"    type: select","    proxies:",_(s),""],v=n("aHR0cHM6Ly9mYXN0bHkuanNkZWxpdnIubmV0L2doL0xveWFsc29sZGllci9jbGFzaC1ydWxlc0ByZWxlYXNl"),y=(b,l)=>[`  ${b}:`,"    type: http",`    behavior: ${l}`,`    url: "${v}/${b}.txt"`,`    path: ./rulesets/loyalsoldier/${b}.txt`,"    interval: 86400"].join(`
`),x=["rule-providers:",y("reject","domain"),y("icloud","domain"),y("apple","domain"),y("google","domain"),y(n("cHJveHk="),"domain"),y("direct","domain"),y("private","domain"),y("gfw","domain"),y("greatfire","domain"),y("tld-not-cn","domain"),y("telegramcidr","ipcidr"),y("cncidr","ipcidr"),y("lancidr","ipcidr"),y("applications","classical"),""],d=["rules:","  - DOMAIN-SUFFIX,acl4.ssr,🎯 全球直连","  - DOMAIN-SUFFIX,local,🎯 全球直连",n("ICAtIERPTUFJTixjbGFzaC5yYXpvcmQudG9wLPCfjq8g5YWo55CD55u06L+e"),"  - DOMAIN,yacd.haishan.me,🎯 全球直连","  - DOMAIN,yacd.metacubex.one,🎯 全球直连","  - DOMAIN,d.metacubex.one,🎯 全球直连","  - DOMAIN-SUFFIX,googleapis.cn,🌐 谷歌服务","  - DOMAIN-SUFFIX,gstatic.com,🌐 谷歌服务","  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,🌐 谷歌服务","  - DOMAIN-SUFFIX,googlevideo.com,📹 油管视频","  - DOMAIN-SUFFIX,googleusercontent.com,🌐 谷歌服务","  - DOMAIN-KEYWORD,youtube,📹 油管视频","  - DOMAIN-SUFFIX,youtube.com,📹 油管视频","  - DOMAIN-SUFFIX,youtu.be,📹 油管视频","  - DOMAIN-KEYWORD,netflix,🎬 奈飞视频","  - DOMAIN-SUFFIX,nflxext.com,🎬 奈飞视频","  - DOMAIN-SUFFIX,nflxso.net,🎬 奈飞视频","  - DOMAIN-SUFFIX,nflxvideo.net,🎬 奈飞视频","  - DOMAIN-SUFFIX,nflximg.com,🎬 奈飞视频","  - DOMAIN-SUFFIX,nflximg.net,🎬 奈飞视频","  - DOMAIN-SUFFIX,netflix.com,🎬 奈飞视频","  - DOMAIN-SUFFIX,netflix.net,🎬 奈飞视频","  - DOMAIN-SUFFIX,bilibili.com,📺 哔哩哔哩","  - DOMAIN-SUFFIX,bilivideo.com,📺 哔哩哔哩","  - DOMAIN-SUFFIX,hdslb.com,📺 哔哩哔哩","  - DOMAIN-KEYWORD,openai,🤖 OpenAI","  - DOMAIN-KEYWORD,chatgpt,🤖 OpenAI","  - DOMAIN-SUFFIX,openai.com,🤖 OpenAI","  - DOMAIN-SUFFIX,chatgpt.com,🤖 OpenAI","  - DOMAIN-SUFFIX,oaistatic.com,🤖 OpenAI","  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 OpenAI","  - DOMAIN-SUFFIX,anthropic.com,🤖 OpenAI","  - DOMAIN-SUFFIX,claude.ai,🤖 OpenAI","  - DOMAIN-SUFFIX,perplexity.ai,🤖 OpenAI","  - DOMAIN-SUFFIX,gemini.google.com,🤖 OpenAI","  - RULE-SET,applications,🎯 全球直连","  - RULE-SET,private,🎯 全球直连","  - RULE-SET,reject,🛑 全球拦截","  - RULE-SET,icloud,🍎 苹果服务","  - RULE-SET,apple,🍎 苹果服务","  - RULE-SET,google,🌐 谷歌服务",n("ICAtIFJVTEUtU0VULHByb3h5LPCfmoAg6IqC54K56YCJ5oup"),"  - RULE-SET,gfw,🚀 节点选择","  - RULE-SET,greatfire,🚀 节点选择","  - RULE-SET,tld-not-cn,🚀 节点选择","  - RULE-SET,direct,🎯 全球直连","  - RULE-SET,lancidr,🎯 全球直连,no-resolve","  - RULE-SET,cncidr,🎯 全球直连,no-resolve","  - RULE-SET,telegramcidr,📲 电报信息,no-resolve","  - GEOIP,LAN,🎯 全球直连,no-resolve","  - GEOIP,CN,🎯 全球直连,no-resolve","  - MATCH,🐟 漏网之鱼"];return[a.join(`
`),c.join(`
`),"",r.join(`
`),x.join(`
`),d.join(`
`),""].join(`
`)}function Ct(t){return JSON.stringify(ot(t.map(re),{dns:j}),null,2)}let wt=n("aHR0cHM6Ly9mYXN0bHkuanNkZWxpdnIubmV0L2doL0FDTDRTU1IvQUNMNFNTUkBtYXN0ZXIvQ2xhc2g="),L=t=>`${wt}/${t}.list`;function Lt(t){let e=t.map(re).filter(c=>c&&c.proto===n("dHJvamFu")),o=j||"223.5.5.5",s=e.map(c=>c.name),i=["[General]","loglevel = notify","internet-test-url = http://www.apple.com/library/test/success.html",n("cHJveHktdGVzdC11cmwgPSBodHRwOi8vd3d3LmdzdGF0aWMuY29tL2dlbmVyYXRlXzIwNA=="),"test-timeout = 3",`dns-server = ${o.replace(/^https?:\/\//,"").replace(/\/.*$/,"")}, 119.29.29.29, system`,"encrypted-dns-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query","ipv6 = true","allow-wifi-access = false","wifi-access-http-port = 6152",n("d2lmaS1hY2Nlc3Mtc29ja3M1LXBvcnQgPSA2MTUz"),n("c2tpcC1wcm94eSA9IDEyNy4wLjAuMSwgMTkyLjE2OC4wLjAvMTYsIDEwLjAuMC4wLzgsIDE3Mi4xNi4wLjAvMTIsIGxvY2FsaG9zdCwgKi5sb2NhbCwgY2FwdGl2ZS5hcHBsZS5jb20="),"exclude-simple-hostnames = true","show-error-page-for-reject = true","",n("W1Byb3h5XQ==")];for(let c of e){let g=c.sni;i.push(`${c.name} = ${n("dHJvamFu")}, ${c.server}, ${c.port}, password=${c.password}, sni=${g}, ws=true, ws-path=${c.path}, ws-headers=Host:${c.host}, skip-cert-verify=false, tfo=true`)}e.length||i.push("Direct = direct"),i.push(""),i.push(n("W1Byb3h5IEdyb3VwXQ=="));let a=s.length?s.join(", "):"DIRECT";return i.push(`🚀 节点选择 = select, 🎯 全球直连, ${a}`),i.push(`🌍 国外媒体 = select, ${P(s)}`),i.push(`📺 哔哩哔哩 = select, ${P(s,{directFirst:!0})}`),i.push(`📹 油管视频 = select, ${P(s,{extraGroups:["🌍 国外媒体"]})}`),i.push(`🎬 奈飞视频 = select, ${P(s,{extraGroups:["🌍 国外媒体"]})}`),i.push(`📲 电报信息 = select, ${P(s)}`),i.push(`🌐 谷歌服务 = select, ${P(s)}`),i.push(`🤖 OpenAI = select, ${P(s)}`),i.push(`Ⓜ️ 微软服务 = select, ${P(s,{directFirst:!0})}`),i.push(`🍎 苹果服务 = select, ${P(s,{directFirst:!0})}`),i.push("🎯 全球直连 = select, DIRECT"),i.push("🛑 全球拦截 = select, REJECT, DIRECT"),i.push(`🐟 漏网之鱼 = select, ${P(s)}`),i.push(""),i.push("[Rule]"),i.push(`RULE-SET,${L("LocalAreaNetwork")},🎯 全球直连`),i.push(`RULE-SET,${L("UnBan")},🎯 全球直连`),i.push(`RULE-SET,${L("BanAD")},🛑 全球拦截`),i.push(`RULE-SET,${L("BanProgramAD")},🛑 全球拦截`),i.push(`RULE-SET,${L("GoogleFCM")},🌐 谷歌服务`),i.push(`RULE-SET,${L("GoogleCN")},🎯 全球直连`),i.push(`RULE-SET,${L("SteamCN")},🎯 全球直连`),i.push(`RULE-SET,${L("Microsoft")},Ⓜ️ 微软服务`),i.push(`RULE-SET,${L("Apple")},🍎 苹果服务`),i.push(`RULE-SET,${L("Telegram")},📲 电报信息`),i.push(`RULE-SET,${L("OpenAi")},🤖 OpenAI`),i.push(`RULE-SET,${L("Claude")},🤖 OpenAI`),i.push(`RULE-SET,${L("Copilot")},🤖 OpenAI`),i.push(`RULE-SET,${L("Netflix")},🌍 国外媒体`),i.push(`RULE-SET,${L("YouTube")},🌍 国外媒体`),i.push(`RULE-SET,${L("Disney")},🌍 国外媒体`),i.push(`RULE-SET,${L("Spotify")},🌍 国外媒体`),i.push(`RULE-SET,${L("TikTok")},🌍 国外媒体`),i.push(`RULE-SET,${L("BiliBili")},📺 哔哩哔哩`),i.push(`RULE-SET,${L(n("UHJveHlNZWRpYQ=="))},🌍 国外媒体`),i.push(`RULE-SET,${L(n("UHJveHlHRldsaXN0"))},🚀 节点选择`),i.push(`RULE-SET,${L("ChinaDomain")},🎯 全球直连`),i.push(`RULE-SET,${L("ChinaCompanyIp")},🎯 全球直连`),i.push(`RULE-SET,${L("ChinaIp")},🎯 全球直连`),i.push("GEOIP,CN,🎯 全球直连"),i.push("FINAL,🐟 漏网之鱼,dns-failed"),i.join(`
`)}function Et(t){let e=t.map(re).filter(a=>a&&(a.proto===n("dmxlc3M=")||a.proto===n("dHJvamFu"))),o=e.map(a=>a.name),s=["[General]","ip-mode = dual",`dns-server = ${(j||"223.5.5.5").replace(/^https?:\/\//,"").replace(/\/.*$/,"")},119.29.29.29,system`,"doh-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query",n("YWxsb3ctdWRwLXByb3h5ID0gdHJ1ZQ=="),"allow-wifi-access = false","sni-sniffing = true",n("c2tpcC1wcm94eSA9IDEyNy4wLjAuMSwxOTIuMTY4LjAuMC8xNiwxMC4wLjAuMC84LDE3Mi4xNi4wLjAvMTIsbG9jYWxob3N0LCoubG9jYWwsY2FwdGl2ZS5hcHBsZS5jb20="),"bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32","",n("W1Byb3h5XQ==")];for(let a of e)if(a.proto===n("dmxlc3M=")){let c=[`${a.server}`,`${a.port}`,"udp=true",`username=${a.uuid}`,"transport=ws",`path=${a.path}`,`host=${a.host}`,`over-tls=${a.tls?"true":"false"}`];a.tls&&(c.push(`tls-name=${a.sni}`),a.alpn&&a.alpn.length&&c.push(`alpn=${a.alpn.join(":")}`),c.push("skip-cert-verify=false")),s.push(`${a.name} = ${n("dmxlc3M=")},${c.join(",")}`)}else{let c=[`${a.server}`,`${a.port}`,`password=${a.password}`,"transport=ws",`path=${a.path}`,`host=${a.host}`,"over-tls=true",`tls-name=${a.sni}`];a.alpn&&a.alpn.length&&c.push(`alpn=${a.alpn.join(":")}`),c.push("skip-cert-verify=false"),s.push(`${a.name} = ${n("dHJvamFu")},${c.join(",")}`)}s.push(""),s.push(n("W1Byb3h5IEdyb3VwXQ=="));let i=o.length?o.join(","):"DIRECT";return s.push(`🚀 节点选择 = select,🎯 全球直连,${i}`),s.push(`🌍 国外媒体 = select,${P(o,{compact:!0})}`),s.push(`📺 哔哩哔哩 = select,${P(o,{directFirst:!0,compact:!0})}`),s.push(`📹 油管视频 = select,${P(o,{extraGroups:["🌍 国外媒体"],compact:!0})}`),s.push(`🎬 奈飞视频 = select,${P(o,{extraGroups:["🌍 国外媒体"],compact:!0})}`),s.push(`📲 电报信息 = select,${P(o,{compact:!0})}`),s.push(`🌐 谷歌服务 = select,${P(o,{compact:!0})}`),s.push(`🤖 OpenAI = select,${P(o,{compact:!0})}`),s.push(`Ⓜ️ 微软服务 = select,${P(o,{directFirst:!0,compact:!0})}`),s.push(`🍎 苹果服务 = select,${P(o,{directFirst:!0,compact:!0})}`),s.push("🎯 全球直连 = select,DIRECT"),s.push("🛑 全球拦截 = select,REJECT,DIRECT"),s.push(`🐟 漏网之鱼 = select,${P(o,{compact:!0})}`),s.push(""),s.push("[Remote Rule]"),s.push(`${L("LocalAreaNetwork")}, policy=🎯 全球直连, tag=局域网, enabled=true`),s.push(`${L("BanAD")}, policy=🛑 全球拦截, tag=广告拦截, enabled=true`),s.push(`${L("BanProgramAD")}, policy=🛑 全球拦截, tag=应用广告, enabled=true`),s.push(`${L("GoogleCN")}, policy=🎯 全球直连, tag=GoogleCN, enabled=true`),s.push(`${L("SteamCN")}, policy=🎯 全球直连, tag=SteamCN, enabled=true`),s.push(`${L("Microsoft")}, policy=Ⓜ️ 微软服务, tag=微软, enabled=true`),s.push(`${L("Apple")}, policy=🍎 苹果服务, tag=苹果, enabled=true`),s.push(`${L("Telegram")}, policy=📲 电报信息, tag=电报, enabled=true`),s.push(`${L("OpenAi")}, policy=🤖 OpenAI, tag=OpenAI, enabled=true`),s.push(`${L("Netflix")}, policy=🌍 国外媒体, tag=Netflix, enabled=true`),s.push(`${L("YouTube")}, policy=🌍 国外媒体, tag=YouTube, enabled=true`),s.push(`${L("Disney")}, policy=🌍 国外媒体, tag=Disney, enabled=true`),s.push(`${L("Spotify")}, policy=🌍 国外媒体, tag=Spotify, enabled=true`),s.push(`${L("TikTok")}, policy=🌍 国外媒体, tag=TikTok, enabled=true`),s.push(`${L("BiliBili")}, policy=📺 哔哩哔哩, tag=哔哩哔哩, enabled=true`),s.push(`${L(n("UHJveHlNZWRpYQ=="))}, policy=🌍 国外媒体, tag=${n("5Luj55CG5aqS5L2T")}, enabled=true`),s.push(`${L(n("UHJveHlHRldsaXN0"))}, policy=🚀 节点选择, tag=${n("5Luj55CG5YiX6KGo")}, enabled=true`),s.push(`${L("ChinaDomain")}, policy=🎯 全球直连, tag=中国域名, enabled=true`),s.push(`${L("ChinaIp")}, policy=🎯 全球直连, tag=中国IP, enabled=true`),s.push(""),s.push("[Rule]"),s.push("GEOIP,CN,🎯 全球直连"),s.push("FINAL,🐟 漏网之鱼"),s.join(`
`)}function kt(t){let e=t.map(re).filter(c=>c&&(c.proto===n("dmxlc3M=")||c.proto===n("dHJvamFu"))),o=e.map(c=>c.name),s=n("aHR0cHM6Ly9mYXN0bHkuanNkZWxpdnIubmV0L2doL2JsYWNrbWF0cml4Ny9pb3NfcnVsZV9zY3JpcHRAbWFzdGVyL3J1bGUvUXVhbnR1bXVsdFg="),i=["[general]","network_check_url=http://www.gstatic.com/generate_204","server_check_url=http://www.gstatic.com/generate_204","profile_img_url=https://fastly.jsdelivr.net/gh/byJoey/cfnew@main/snippets/logo.png","dns_exclusion_list=*.cmpassport.com, *.jegotrip.com.cn, *.icloud.com, *.icloud.com.cn, *.apple.com, *.weibo.com, *.qq.com","running_mode_trigger=filter","","[dns]",`server=${(j||"223.5.5.5").replace(/^https?:\/\//,"").replace(/\/.*$/,"")}`,"server=119.29.29.29","server=https://223.5.5.5/dns-query","server=https://1.12.12.12/dns-query","","[server_local]"];for(let c of e)if(c.proto===n("dmxlc3M=")){let g=[`${c.server}:${c.port}`,"method=none",`password=${c.uuid}`,`obfs=${c.tls?"wss":"ws"}`,`obfs-host=${c.host}`,`obfs-uri=${c.path}`];c.tls&&g.push("tls-verification=true","tls13=true"),g.push(`tag=${c.name}`),i.push(`${n("dmxlc3M=")}=${g.join(", ")}`)}else{let g=[`${c.server}:${c.port}`,`password=${c.password}`,"over-tls=true",`tls-host=${c.sni}`,"obfs=wss",`obfs-host=${c.host}`,`obfs-uri=${c.path}`,"tls-verification=true",`tag=${c.name}`];i.push(`${n("dHJvamFu")}=${g.join(", ")}`)}i.push(""),i.push("[policy]");let a=o.length?o.join(", "):"direct";return i.push(`static=🚀 节点选择, ${a}, direct, img-url=${n("aHR0cHM6Ly9mYXN0bHkuanNkZWxpdnIubmV0L2doL0tvb2xzb24vUXVyZUBtYXN0ZXIvSWNvblNldC9Db2xvci9Qcm94eS5wbmc=")}`),i.push(`static=🌍 国外媒体, ${P(o)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ForeignMedia.png`),i.push(`static=📺 哔哩哔哩, ${P(o,{directFirst:!0})}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/bilibili.png`),i.push(`static=📹 油管视频, ${P(o,{extraGroups:["🌍 国外媒体"]})}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png`),i.push(`static=🎬 奈飞视频, ${P(o,{extraGroups:["🌍 国外媒体"]})}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png`),i.push(`static=📲 电报信息, ${P(o)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png`),i.push(`static=🌐 谷歌服务, ${P(o)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Google.png`),i.push(`static=🤖 OpenAI, ${P(o)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png`),i.push(`static=Ⓜ️ 微软服务, ${P(o,{directFirst:!0})}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Microsoft.png`),i.push(`static=🍎 苹果服务, ${P(o,{directFirst:!0})}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Apple.png`),i.push("static=🎯 全球直连, direct, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png"),i.push("static=🛑 全球拦截, reject, direct, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Advertising.png"),i.push(`static=🐟 漏网之鱼, ${P(o)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Final.png`),i.push(""),i.push("[filter_remote]"),i.push(`${s}/Lan/Lan.list, tag=局域网, force-policy=🎯 全球直连, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Advertising/Advertising.list, tag=广告拦截, force-policy=🛑 全球拦截, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Microsoft/Microsoft.list, tag=微软, force-policy=Ⓜ️ 微软服务, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Apple/Apple.list, tag=苹果, force-policy=🍎 苹果服务, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Telegram/Telegram.list, tag=电报, force-policy=📲 电报信息, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Google/Google.list, tag=谷歌, force-policy=🌐 谷歌服务, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/OpenAI/OpenAI.list, tag=OpenAI, force-policy=🤖 OpenAI, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Claude/Claude.list, tag=Claude, force-policy=🤖 OpenAI, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/YouTube/YouTube.list, tag=YouTube, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Netflix/Netflix.list, tag=Netflix, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Disney/Disney.list, tag=Disney, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Spotify/Spotify.list, tag=Spotify, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/TikTok/TikTok.list, tag=TikTok, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/BiliBili/BiliBili.list, tag=哔哩哔哩, force-policy=📺 哔哩哔哩, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/Global/Global.list, tag=全球加速, force-policy=🚀 节点选择, update-interval=86400, opt-parser=false, enabled=true`),i.push(`${s}/ChinaMax/ChinaMax.list, tag=中国直连, force-policy=🎯 全球直连, update-interval=86400, opt-parser=false, enabled=true`),i.push(""),i.push("[filter_local]"),i.push("geoip, cn, 🎯 全球直连"),i.push("final, 🐟 漏网之鱼"),i.join(`
`)}let Ge=n("aHR0cHM6Ly93d3cudnBuZ2F0ZS5uZXQvYXBpL2lwaG9uZS8="),St=n("b3BlbnZwbg=="),Nt=n("ZGlhbGVyLXByb3h5"),Yt=n("cHVibGljLXZwbg=="),$t="219.100.37.",Tt=1800*1e3,Ie=null,Je=0,Ce={};function ce(t,e){Ce[e]||(Ce[e]=new RegExp("^[ \\t]*"+e+"[ \\t]+(.+?)[ \\t]*$","m"));let o=t.match(Ce[e]);return o?o[1].trim():""}function we(t,e){let o=t.match(new RegExp("<"+e+">([\\s\\S]*?)<\\/"+e+">"));return o?o[1].trim():""}function Le(t,e){return t.split(`
`).map(o=>o.trim()).filter(o=>o).map(o=>e+o).join(`
`)}let We=6e3;function Ee(t,e=!1){let o=t.replace(/\s/g,"");return e||o.length<=We?n(o):n(o.slice(0,We))}function Ut(t){let e=[];for(let i of t.split(`
`)){let a=i.trim();if(!a||a.charAt(0)==="*"||a.charAt(0)==="#")continue;let c=a.split(",");if(c.length<15||(c[0]||"").indexOf(Yt)===0||(c[1]||"").indexOf($t)===0)continue;let g=c[c.length-1];!g||g.length<100||e.push({国家:(c[6]||"").toUpperCase()||"XX",速度:parseInt(c[4],10)||0,配置64:g})}e.sort((i,a)=>a.速度-i.速度);let o=[],s=null;for(let i of e){let a="";try{a=Ee(i.配置64),ce(a,"remote")||(a=Ee(i.配置64,!0))}catch{continue}if((ce(a,"proto")||"tcp").toLowerCase()!=="tcp")continue;let c=ce(a,"remote").split(/\s+/);if(c[0]){if(!s){try{let g=Ee(i.配置64,!0),r={ca:we(g,"ca"),cert:we(g,"cert"),key:we(g,"key")};r.ca&&r.cert&&r.key&&(s=r)}catch{}if(!s)continue}o.push({国家:i.国家,地址:c[0],端口:parseInt(c[1],10)||443,加密:ce(a,"cipher")||"AES-128-CBC",摘要:ce(a,"auth")||"SHA1"})}}return{节点列表:o,证书:s}}async function Pt(){let t=Date.now();if(Ie&&t-Je<Tt)return Ie;let e="",o=null;for(let i of[Ge,Ge.replace(/^https:/,"http:")])try{let a=await fetch(i,{headers:{"User-Agent":"Mozilla/5.0",Accept:"text/plain"},cf:{cacheTtl:1800,cacheEverything:!0}});if(!a.ok){o=new Error("节点源返回 "+a.status);continue}e=await a.text();break}catch(a){o=a}if(!e)throw o||new Error("节点源没有返回内容");let s=Ut(e);if(!s.节点列表.length||!s.证书)throw new Error("没解析出能用的节点");return Ie=s,Je=t,s}async function Ht(t){let e="⚡ CF前置",o="🏠 家宽自动",s="🏠 家宽节点",i="🚀 节点选择",a=t.map(re).filter(Y=>Y&&(Y.proto===n("dmxlc3M=")||Y.proto===n("dHJvamFu"))),c=a.filter(Y=>Y.tls),g=c.length?c:a,r=g.map(Y=>Y.name),v=j||"https://223.5.5.5/dns-query",{节点列表:y,证书:x}=await Pt(),d={},b=y.map(Y=>(d[Y.国家]=(d[Y.国家]||0)+1,{...Y,名称:"🏠 "+Y.国家+"-家宽-"+String(d[Y.国家]).padStart(2,"0")})),l=["# cfnew 家宽订阅：CF 节点带路，落地是住宅宽带","# 内核要 1.19.25 以上，老内核不认这类节点","# 节点是网友共享的，掉线很正常，家宽自动会自己往下换","mixed-port: 7890","allow-lan: false","mode: rule","log-level: info","ipv6: false","unified-delay: true","tcp-concurrent: true","external-controller: 127.0.0.1:9090","dns:","  enable: true","  ipv6: false","  enhanced-mode: fake-ip","  fake-ip-range: 198.18.0.1/16","  nameserver:","    - "+v,"    - https://1.1.1.1/dns-query",""],h=["proxies:"];for(let Y of g)h.push(qe(Y));b.forEach((Y,se)=>{let ie=['  - name: "'+Y.名称+'"',"    type: "+St,"    server: "+Y.地址,"    port: "+Y.端口,"    proto: tcp","    username: vpn","    password: vpn","    cipher: "+Y.加密,"    auth: "+Y.摘要,"    udp: false","    handshake-timeout: 30","    remote-dns-resolve: true","    dns: [ 8.8.8.8, 1.1.1.1 ]"];r.length&&ie.push("    "+Nt+': "'+e+'"'),se===0?(ie.push("    ca: &jkca |-",Le(x.ca,"      ")),ie.push("    cert: &jkcert |-",Le(x.cert,"      ")),ie.push("    key: &jkkey |-",Le(x.key,"      "))):ie.push("    ca: *jkca","    cert: *jkcert","    key: *jkkey"),h.push(ie.join(`
`))});let u=Y=>Y.map(se=>'      - "'+se+'"').join(`
`),w=b.map(Y=>Y.名称),$=b.slice().sort((Y,se)=>Y.国家===se.国家?0:Y.国家<se.国家?-1:1).map(Y=>Y.名称),M=[n("cHJveHktZ3JvdXBzOg==")];r.length&&M.push('  - name: "'+e+'"',"    type: url-test","    url: https://www.gstatic.com/generate_204","    interval: 300","    tolerance: 50","    proxies:",u(r)),M.push('  - name: "'+o+'"',"    type: fallback","    url: https://www.gstatic.com/generate_204","    interval: 1800","    lazy: true","    proxies:",u(w)),M.push('  - name: "'+s+'"',"    type: select","    proxies:",u($));let O=['      - "'+o+'"','      - "'+s+'"'];r.length&&O.push('      - "'+e+'"'),O.push("      - DIRECT"),M.push('  - name: "'+i+'"',"    type: select","    proxies:",O.join(`
`));let ee=["rules:","  - GEOIP,LAN,DIRECT,no-resolve","  - GEOIP,CN,DIRECT,no-resolve","  - MATCH,"+i];return l.concat(h,[""],M,[""],ee,[""]).join(`
`)}async function Mt(t,e,o=null){o||(o=new URL(t.url));let s=[],i=o.hostname,a=o.searchParams.get("target")||"base64";if(["vg","jk",n("amlha3Vhbg==")].includes(a.toLowerCase())&&!he)return new Response("家宽链式没开。去配置管理勾上「开启家宽链式」，或者加环境变量 jk=yes。",{status:403,headers:{"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-store"}});let g=oe(!1),r=null;F&&(r=`${V||"cloudflare-ech.com"}+${j||"https://223.5.5.5/dns-query"}`);async function v(l){A&&s.push(...Rt(l,e,i,r,!1,g)),z&&s.push(...await Dt(l,e,i,r,!1,g)),G&&s.push(...Xe(l,e,i,r,!1,g))}if($e)if(C==="CUSTOM")await v([{ip:i,isp:"原生地址"}]);else try{await v([{ip:i,isp:"原生地址"}])}catch{C||(C="CF");let h=await xe(C);if(h){S=h.domain+":"+h.port;let u=[{ip:h.domain,isp:n("UHJveHlJUC0=")+C}];await v(u)}else await v([{ip:i,isp:"原生地址"}])}let y=R.length>0||K.length>0;if(!q)if(y){if(R.length>0&&ge&&await v(R),K.length>0&&fe){let l=K.map(h=>({ip:h.domain,port:h.port,isp:h.name||h.domain}));await v(l)}}else{if(fe){let l=ft.map(h=>({ip:h.domain,isp:h.name||h.domain}));await v(l)}if(ge&&!U)try{let l=await At();l.length>0&&await v(l)}catch{C||(C="CF");let h=await xe(C);if(h){S=h.domain+":"+h.port;let u=[{ip:h.domain,isp:n("UHJveHlJUC0=")+C}];await v(u)}}if(Ye)try{let l=await Bt();l.length>0&&(A&&s.push(...Ot(l,e,i,r,!1,g)),z&&s.push(...await zt(l,e,i,r,!1,g)),G&&s.push(...Xe(l,e,i,r,!1,g)))}catch{C||(C="CF");let h=await xe(C);if(h){S=h.domain+":"+h.port;let u=[{ip:h.domain,isp:n("UHJveHlJUC0=")+C}];await v(u)}}}if(s.length===0){let u=`${atob("dmxlc3M=")}://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent("所有节点获取失败")}`;s.push(u)}let x,d="text/plain; charset=utf-8";switch(a.toLowerCase()){case atob("Y2xhc2g="):case atob("Y2xhc2hy"):case n("c3Rhc2g="):case"meta":case n("Y2xhc2htZXRh"):x=It(s),d="text/yaml; charset=utf-8";break;case"vg":case"jk":case n("amlha3Vhbg=="):try{x=await Ht(s)}catch(l){return new Response("家宽节点暂时拉不到："+(l&&l.message?l.message:l)+`
过几分钟再更新，客户端会先用着上一份。`,{status:503,headers:{"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-store"}})}d="text/yaml; charset=utf-8";break;case atob("c3VyZ2U="):case atob("c3VyZ2Uy"):case atob("c3VyZ2Uz"):case atob("c3VyZ2U0"):x=Lt(s),d="text/plain; charset=utf-8";break;case atob("cXVhbnR1bXVsdA=="):case atob("cXVhbng="):case n("cXVhbng="):x=kt(s),d="text/plain; charset=utf-8";break;case atob("c3M="):case atob("c3Ny"):x=btoa(s.join(`
`));break;case atob("djJyYXk="):x=btoa(s.join(`
`));break;case atob("bG9vbg=="):x=Et(s),d="text/plain; charset=utf-8";break;case atob("c2luZ2JveA=="):case n("c2luZy1ib3g="):case n("c2luZ2JveA=="):x=Ct(s),d="application/json; charset=utf-8";break;default:x=btoa(s.join(`
`))}let b={"Content-Type":d,"Cache-Control":"no-store, no-cache, must-revalidate, max-age=0"};return d.startsWith("application/json")&&(b.Link='</rules-license>; rel="license"'),F&&(b["X-ECH-Status"]="ENABLED",r&&(b["X-ECH-Config-Length"]=String(r.length))),new Response(x,{headers:b})}function Rt(t,e,o,s=null,i=!1,a=null){let c=[80,8080,8880,2052,2082,2086,2095],g=[443,2053,2083,2087,2096,8443],r=[443],v=B?[]:[80],y=[],x="/?ed=2048",d=atob("dmxlc3M="),b=a||oe(i);for(let l of t){let h=l.ip.includes(":")?`[${l.ip}]`:l.ip,u=[];if(l.port){let w=l.port;g.includes(w)?u.push({port:w,tls:!0}):c.includes(w)?B||u.push({port:w,tls:!1}):u.push({port:w,tls:!0})}else r.forEach(w=>{u.push({port:w,tls:!0})}),v.forEach(w=>{u.push({port:w,tls:!1})});for(let{port:w,tls:$}of u){let M=b(l);if($){let O=new URLSearchParams({encryption:"none",security:"tls",sni:o,fp:"chrome",type:"ws",host:o,path:x});if(Ze(O),F){let ee=j||"https://223.5.5.5/dns-query",Y=V||"cloudflare-ech.com";O.set("ech",`${Y}+${ee}`)}y.push(`${d}://${e}@${h}:${w}?${O.toString()}#${encodeURIComponent(M)}`)}else{let O=new URLSearchParams({encryption:"none",security:"none",type:"ws",host:o,path:x});y.push(`${d}://${e}@${h}:${w}?${O.toString()}#${encodeURIComponent(M)}`)}}}return y}async function Dt(t,e,o,s=null,i=!1,a=null){let c=[80,8080,8880,2052,2082,2086,2095],g=[443,2053,2083,2087,2096,8443],r=[443],v=B?[]:[80],y=[],x="/?ed=2048",d=W||e,b=a||oe(i);for(let l of t){let h=l.ip.includes(":")?`[${l.ip}]`:l.ip,u=[];if(l.port){let w=l.port;g.includes(w)?u.push({port:w,tls:!0}):c.includes(w)?B||u.push({port:w,tls:!1}):u.push({port:w,tls:!0})}else r.forEach(w=>{u.push({port:w,tls:!0})}),v.forEach(w=>{u.push({port:w,tls:!1})});for(let{port:w,tls:$}of u){let M=b(l);if($){let O=new URLSearchParams({security:"tls",sni:o,fp:"chrome",type:"ws",host:o,path:x});if(Ze(O),F){let ee=j||"https://223.5.5.5/dns-query",Y=V||"cloudflare-ech.com";O.set("ech",`${Y}+${ee}`)}y.push(`${atob("dHJvamFuOi8v")}${d}@${h}:${w}?${O.toString()}#${encodeURIComponent(M)}`)}else{let O=new URLSearchParams({security:"none",type:"ws",host:o,path:x});y.push(`${atob("dHJvamFuOi8v")}${d}@${h}:${w}?${O.toString()}#${encodeURIComponent(M)}`)}}}return y}async function Ve(t){return Qe("md5").update(t).digest("hex")}async function At(){let t={ctcc:"电信",cucc:"联通",cmcc:"移动",bgp:"多线",ipv6:"IPv6"},e=J("ipv4","")===""||J("ipv4","yes")!=="no",o=J("ipv6","")===""||J("ipv6","yes")!=="no",s=J("ispMobile","")===""||J("ispMobile","yes")!=="no",i=J("ispUnicom","")===""||J("ispUnicom","yes")!=="no",a=J("ispTelecom","")===""||J("ispTelecom","yes")!=="no";try{let c=String(Date.now()),g=await Ve(n("RGRsVHh0TjBzVU91")),r=await Ve(g+n("NzBjbG91ZGZsYXJlYXBpa2V5")+c),v=await fetch(`${n("aHR0cHM6Ly9hcGkudW91aW4uY29tL2luZGV4LnBocC9pbmRleC9DbG91ZGZsYXJl")}?key=${r}&time=${c}`,{headers:{"User-Agent":"Mozilla/5.0"}});if(!v.ok)return[];let y=await v.json(),x=y&&y.data;if(!x)return[];let d=[];for(let b of Object.keys(t)){let l=b==="ipv6";if(l&&!o||!l&&!e)continue;let h=t[b];if(h==="移动"&&!s||h==="联通"&&!i||h==="电信"&&!a)continue;let u=x[b],w=u&&Array.isArray(u.info)?u.info:[];for(let $ of w){let M=be($&&$.ip);M&&d.push({isp:h,ip:M,colo:""})}}return d}catch{}return[]}function Ft(t){let e=String(t||"").trim(),o=je,s=e.toLowerCase();s.startsWith(Fe)?(o=Ke,e=e.slice(Fe.length)):s.startsWith(Ae)?(o=gt,e=e.slice(Ae.length)):s.startsWith(Re)?e=e.slice(Re.length):s.startsWith(De)&&(e=e.slice(De.length));let i=e.indexOf("/");if(i>=0&&(e=e.slice(0,i)),!e)throw new Error(ae);let[a,c]=e.split("@").reverse(),g,r,v,y;if(c){let b=c.split(":");if(b.length!==2)throw new Error(ae);[g,r]=b}let x=a.split(":"),d=x.pop();if(y=Number(d),isNaN(y)){if(o===je)throw new Error(ae);x.push(d),y=o===Ke?443:80}if(v=x.join(":"),!v)throw new Error(ae);if(v.includes(":")&&!/^\[.*\]$/.test(v))throw new Error(ae);return{username:g,password:r,hostname:v,socksPort:y,kind:o}}async function jt(t,e=null){e||(e=E);let o=new URL(t.url),s=t.headers.get("Cookie")||"",i=null;if(s){let y=s.split(";").map(x=>x.trim());for(let x of y)if(x.startsWith("preferredLanguage=")){i=x.split("=")[1];break}}let a=!1;if(i==="fa"||i==="fa-IR")a=!0;else if(i==="zh"||i==="zh-CN")a=!1;else{let y=t.headers.get("Accept-Language")||"";a=y.split(",")[0].split("-")[0].toLowerCase()==="fa"||y.includes("fa-IR")||y.includes("fa")}let c=a?"fa-IR":"zh-CN",r={zh:{title:n("6K6i6ZiF5Lit5b+D"),subtitle:"多客户端支持 • 智能优选 • 一键生成",selectClient:"[ 选择客户端 ]",systemStatus:"[ 系统状态 ]",configManagement:"[ 配置管理 ]",relatedLinks:"[ 相关链接 ]",checking:"检测中...",workerRegion:"Worker地区: ",detectionMethod:"检测方式: ",proxyIPStatus:n("UHJveHlJUOeKtuaAgTog"),currentIP:"当前使用IP: ",regionMatch:"地区匹配: ",selectionLogic:"选择逻辑: ",kvStatusChecking:"检测KV状态中...",kvEnabled:"✅ KV存储已启用，可以使用配置管理功能",kvDisabled:"⚠️ KV存储未启用或未配置",specifyRegion:"指定地区 (wk):",autoDetect:n("5a6Y5pa555u06L+e"),saveRegion:"保存地区配置",protocolSelection:n("5Y2P6K6u6YCJ5oupOg=="),enableProtoV:n("5ZCv55SoIFZMRVNTIOWNj+iurg=="),enableProtoT:n("5ZCv55SoIFRyb2phbiDljY/orq4="),enableXhttp:n("5ZCv55SoIHhodHRwIOWNj+iurg=="),altPassword:n("VHJvamFuIOWvhueggSAo5Y+v6YCJKTo="),customPath:"自定义路径 (d):",customIP:n("6Ieq5a6a5LmJUHJveHlJUCAocCk6"),preferredIPs:"优选IP列表 (yx):",preferredIPsURL:"优选IP来源URL (yxURL):",latencyTest:"延迟测试",latencyTestIP:"测试IP/域名:",latencyTestIPPlaceholder:"输入IP或域名，多个用逗号分隔",latencyTestPort:"端口:",startTest:"开始测试",stopTest:"停止测试",testResult:"测试结果:",addToYx:"添加到优选列表",addSelectedToYx:"添加选中项到优选列表",selectAll:"全选",deselectAll:"取消全选",testingInProgress:"测试中...",testComplete:"测试完成",latencyMs:"延迟",timeout:"超时",ipSource:"IP来源:",manualInput:"手动输入",cfRandomIP:"CF随机IP",urlFetch:"URL获取",randomCount:"生成数量:",fetchURL:"获取URL:",fetchURLPlaceholder:"输入优选IP的URL地址",generateIP:"生成IP",fetchIP:"获取IP",socks5Config:n("5Luj55CG6YWN572uIChzKTo="),customHomepage:"自定义首页URL (homepage):",customHomepagePlaceholder:"例如: https://example.com",customHomepageHint:"设置自定义URL作为首页伪装。访问根路径 / 时将显示该URL的内容。留空则显示默认终端页面。",saveConfig:"保存配置",advancedControl:"高级控制",subscriptionConverter:n("6K6i6ZiF6L2s5o2i5Zyw5Z2AOg=="),builtinPreferred:"内置优选类型:",enablePreferredDomain:"启用优选域名",enablePreferredIP:"启用优选 IP",enableNativeAddress:"启用原生地址",enableGitHubPreferred:"启用自定义优选",jkSection:"家宽链式",jkEnable:"开启家宽链式",jkHint:n("5byA5LqG5LmL5ZCO5a6i5oi356uv5YiX6KGo5aSa5LiA5Liq44CMQ0xBU0gg5a625a6944CN44CCQ0Yg6IqC54K55bim6Lev77yM5Ye65Y+j5o2i5oiQ5pel5pys44CB6Z+p5Zu9562J5Zyw55qE5a625bqt5a695bim44CC6KaBIENsYXNoIE1ldGEg5YaF5qC4IDEuMTkuMjUg5Lul5LiK5omN6K6k77yMQ2xhc2ggVmVyZ2UgUmV244CBRmxDbGFzaOOAgUNNRkEg6YO96KGM44CC6IqC54K55piv572R5Y+L5YWx5Lqr55qE77yM5pe25LiN5pe25Lya5o6J77yM6K6i6ZiF6YeM5Lya6Ieq5bex5o2i44CC"),jkClient:"CLASH 家宽",allowAPIManagement:"允许API管理 (ae):",regionMatching:"地区匹配 (rm):",downgradeControl:n("5Ye656uZ5pa55byPIChxaik6"),tlsControl:"TLS控制 (dkby):",preferredControl:"优选控制 (yxby):",saveAdvanced:"保存高级配置",loading:"加载中...",currentConfig:"📍 当前路径配置",refreshConfig:"刷新配置",resetConfig:"重置配置",subscriptionCopied:n("6K6i6ZiF6ZO+5o6l5bey5aSN5Yi2"),autoSubscriptionCopied:n("6Ieq5Yqo6K+G5Yir6K6i6ZiF6ZO+5o6l5bey5aSN5Yi277yM5a6i5oi356uv6K6/6Zeu5pe25Lya5qC55o2uVXNlci1BZ2VudOiHquWKqOivhuWIq+W5tui/lOWbnuWvueW6lOagvOW8jw=="),altPasswordPlaceholder:"留空则自动使用 UUID",altPasswordHint:n("6K6+572u6Ieq5a6a5LmJIFRyb2phbiDlr4bnoIHjgILnlZnnqbrliJnkvb/nlKggVVVJROOAguWuouaIt+err+S8muiHquWKqOWvueWvhueggei/m+ihjCBTSEEyMjQg5ZOI5biM44CC"),protocolHint:n("5Y+v5Lul5ZCM5pe25ZCv55So5aSa5Liq5Y2P6K6u44CC6K6i6ZiF5bCG55Sf5oiQ6YCJ5Lit5Y2P6K6u55qE6IqC54K544CCPGJyPuKAoiBWTEVTUyBXUzog5Z+65LqOIFdlYlNvY2tldCDnmoTmoIflh4bljY/orq48YnI+4oCiIFRyb2phbjog5L2/55SoIFNIQTIyNCDlr4bnoIHorqTor4E8YnI+4oCiIHhodHRwOiDln7rkuo4gSFRUUCBQT1NUIOeahOS8quijheWNj+iuru+8iOmcgOimgee7keWumuiHquWumuS5ieWfn+WQjeW5tuW8gOWQryBnUlBD77yJ"),enableECH:"启用 ECH (Encrypted Client Hello)",enableECHHint:n("5ZCv55So5ZCO77yM5q+P5qyh5Yi35paw6K6i6ZiF5pe25Lya6Ieq5Yqo5LuOIERvSCDojrflj5bmnIDmlrDnmoQgRUNIIOmFjee9ruW5tua3u+WKoOWIsOmTvuaOpeS4rQ=="),customDNS:"自定义 DNS 服务器",customDNSPlaceholder:"例如: https://223.5.5.5/dns-query",customDNSHint:"用于ECH配置查询的DNS服务器地址（DoH格式）",customECHDomain:"自定义 ECH 域名",customECHDomainPlaceholder:"例如: cloudflare-ech.com",customECHDomainHint:"ECH配置中使用的域名，留空则使用默认值",alpn:"TLS ALPN",alpnDefault:"默认（留空，由客户端协商）",alpnHint:"仅添加到 TLS 节点链接参数；留空则不写 alpn。",saveProtocol:n("5L+d5a2Y5Y2P6K6u6YWN572u"),subscriptionConverterPlaceholder:"默认: https://url.v1.mk/sub",subscriptionConverterHint:n("6K6i6ZiF6L2s5o2i5bey5YaF6YOo5a6e546w77yM5peg6ZyA5aSW6YOoIEFQSeOAguatpOmhueS7heS9nOWFvOWuueS/neeVme+8jOWPr+eVmeepuuOAgg=="),builtinPreferredHint:n("5o6n5Yi26K6i6ZiF5Lit5YyF5ZCr5ZOq5Lqb5YaF572u5LyY6YCJ6IqC54K544CC6buY6K6k5YWo6YOo5ZCv55So44CC"),apiEnabledDefault:"默认（关闭API）",apiEnabledYes:"开启API管理",apiEnabledHint:"⚠️ 安全提醒：开启后允许通过API动态添加优选IP。建议仅在需要时开启。",regionMatchingDefault:"默认（启用地区匹配）",regionMatchingNo:"关闭地区匹配",regionMatchingHint:'设置为"关闭"时不进行地区智能匹配',downgradeControlDefault:n("5LyY5YWI6LWw5Luj55CG77yI6buY6K6k77yJ"),downgradeControlNo:n("5LyY5YWI55u06L+e77yM5aSx6LSl5YaN6LWw5Luj55CG"),downgradeControlOnly:n("5Y+q6LWw5Luj55CG77yM5LiN5Zue6JC9"),downgradeControlHint:n("5rKh5aGr5Luj55CG5pe25LiJ5Liq6YCJ6aG56YO95LiA5qC377yM6YO95piv55u06L+e44CC5Y+q6LWw5Luj55CG5pe26L+e5LiN5LiK5bCx5pat5byA77yM5Ye65Y+jIElQIOS4jeS8mua8jw=="),tlsControlDefault:"默认（保留所有节点）",tlsControlYes:"仅TLS节点",tlsControlHint:'设置为"仅TLS节点"时只生成带TLS的节点，不生成非TLS节点（如80端口）',preferredControlDefault:"默认（启用优选）",preferredControlYes:"关闭优选",preferredControlHint:'设置为"关闭优选"时只使用原生地址，不生成优选IP和域名节点',regionNames:{CF:n("8J+MkCDlrpjmlrnnm7Tov54="),HK:"🇭🇰 香港",US:"🇺🇸 美国",SG:"🇸🇬 新加坡",JP:"🇯🇵 日本",KR:"🇰🇷 韩国",DE:"🇩🇪 德国",SE:"🇸🇪 瑞典",NL:"🇳🇱 荷兰",FI:"🇫🇮 芬兰",GB:"🇬🇧 英国"},terminal:"终端 v3.1",githubProject:"GitHub 项目",优选工具:"优选工具",autoDetectClient:"自动识别",selectionLogicText:"同地区 → 邻近地区 → 其他地区",customIPDisabledHint:n("5L2/55So6Ieq5a6a5LmJUHJveHlJUOaXtu+8jOWcsOWMuumAieaLqeW3suemgeeUqA=="),customIPMode:n("6Ieq5a6a5LmJUHJveHlJUOaooeW8jyAocOWPmOmHj+WQr+eUqCk="),customIPModeDesc:"自定义IP模式 (已禁用地区匹配)",usingCustomProxyIP:n("5L2/55So6Ieq5a6a5LmJUHJveHlJUDog"),customIPConfig:" (p变量配置)",customIPModeDisabled:"自定义IP模式，地区选择已禁用",manualRegion:"手动指定地区",manualRegionDesc:" (手动指定)",proxyIPAvailable:n("MTAvMTAg5Y+v55SoIChQcm94eUlQ5Z+f5ZCN6aKE6K6+5Y+v55SoKQ=="),smartSelection:"智能就近选择中",sameRegionIP:"同地区IP可用 (1个)",cloudflareDetection:n("5a6Y5pa555u06L+e"),detectionFailed:"检测失败",apiTestResult:"API检测结果: ",apiTestTime:"检测时间: ",apiTestFailed:"API检测失败: ",unknownError:"未知错误",apiTestError:"API测试失败: ",kvNotConfigured:"KV存储未配置，无法使用配置管理功能。\\n\\n请在Cloudflare Workers中:\\n1. 创建KV命名空间\\n2. 绑定环境变量 C\\n3. 重新部署代码",kvNotEnabled:"KV存储未配置",kvCheckFailed:"KV存储检测失败: 响应格式错误",kvCheckFailedStatus:"KV存储检测失败 - 状态码: ",kvCheckFailedError:"KV存储检测失败 - 错误: "},fa:{title:"مرکز اشتراک",subtitle:"پشتیبانی چند کلاینت • انتخاب هوشمند • تولید یک کلیکی",selectClient:"[ انتخاب کلاینت ]",systemStatus:"[ وضعیت سیستم ]",configManagement:"[ مدیریت تنظیمات ]",relatedLinks:"[ لینک‌های مرتبط ]",checking:"در حال بررسی...",workerRegion:"منطقه Worker: ",detectionMethod:"روش تشخیص: ",proxyIPStatus:n("2YjYtti524zYqiBQcm94eUlQOiA="),currentIP:"IP فعلی: ",regionMatch:"تطبیق منطقه: ",selectionLogic:"منطق انتخاب: ",kvStatusChecking:"در حال بررسی وضعیت KV...",kvEnabled:"✅ ذخیره‌سازی KV فعال است، می‌توانید از مدیریت تنظیمات استفاده کنید",kvDisabled:"⚠️ ذخیره‌سازی KV فعال نیست یا پیکربندی نشده است",specifyRegion:"تعیین منطقه (wk):",autoDetect:"اتصال مستقیم رسمی",saveRegion:"ذخیره تنظیمات منطقه",protocolSelection:"انتخاب پروتکل:",enableProtoV:n("2YHYudin2YTigIzYs9in2LLbjCDZvtix2YjYqtqp2YQgVkxFU1M="),enableProtoT:n("2YHYudin2YTigIzYs9in2LLbjCDZvtix2YjYqtqp2YQgVHJvamFu"),enableXhttp:"فعال‌سازی پروتکل xhttp",enableECH:"فعال‌سازی ECH (Encrypted Client Hello)",enableECHHint:"پس از فعال‌سازی، در هر بار تازه‌سازی اشتراک، پیکربندی ECH به‌روز به‌طور خودکار از DoH دریافت شده و به لینک‌ها اضافه می‌شود",customDNS:"سرور DNS سفارشی",customDNSPlaceholder:"مثال: https://223.5.5.5/dns-query",customDNSHint:"آدرس سرور DNS برای جستجوی پیکربندی ECH (فرمت DoH)",customECHDomain:"دامنه ECH سفارشی",customECHDomainPlaceholder:"مثال: cloudflare-ech.com",customECHDomainHint:"دامنه استفاده شده در پیکربندی ECH، خالی بگذارید تا از مقدار پیش‌فرض استفاده شود",altPassword:n("2LHZhdiyINi52KjZiNixIFRyb2phbiAo2KfYrtiq24zYp9ix24wpOg=="),customPath:"مسیر سفارشی (d):",customIP:n("UHJveHlJUCDYs9mB2KfYsdi024wgKHApOg=="),preferredIPs:"لیست IP ترجیحی (yx):",preferredIPsURL:"URL منبع IP ترجیحی (yxURL):",latencyTest:"تست تاخیر",latencyTestIP:"IP/دامنه تست:",latencyTestIPPlaceholder:"IP یا دامنه وارد کنید، چند مورد با کاما جدا شوند",latencyTestPort:"پورت:",startTest:"شروع تست",stopTest:"توقف تست",testResult:"نتیجه تست:",addToYx:"افزودن به لیست ترجیحی",addSelectedToYx:"افزودن موارد انتخاب شده",selectAll:"انتخاب همه",deselectAll:"لغو انتخاب",testingInProgress:"در حال تست...",testComplete:"تست کامل شد",latencyMs:"تاخیر",timeout:"زمان تمام شد",ipSource:"منبع IP:",manualInput:"ورودی دستی",cfRandomIP:"IP تصادفی CF",urlFetch:"دریافت از URL",randomCount:"تعداد تولید:",fetchURL:"URL دریافت:",fetchURLPlaceholder:"آدرس URL لیست IP را وارد کنید",generateIP:"تولید IP",fetchIP:"دریافت IP",socks5Config:n("2KrZhti424zZhdin2Kog2b7YsdmI2qnYs9uMIChzKTo="),customHomepage:"URL صفحه اصلی سفارشی (homepage):",customHomepagePlaceholder:"مثال: https://example.com",customHomepageHint:"تنظیم URL سفارشی به عنوان استتار صفحه اصلی. هنگام دسترسی به مسیر اصلی / محتوای این URL نمایش داده می‌شود. اگر خالی بگذارید صفحه ترمینال پیش‌فرض نمایش داده می‌شود.",saveConfig:"ذخیره تنظیمات",advancedControl:"کنترل پیشرفته",subscriptionConverter:"آدرس تبدیل اشتراک:",builtinPreferred:"نوع ترجیحی داخلی:",enablePreferredDomain:"فعال‌سازی دامنه ترجیحی",enablePreferredIP:"فعال‌سازی IP ترجیحی",enableNativeAddress:"فعال‌سازی آدرس اصلی",enableGitHubPreferred:"فعال‌سازی ترجیح سفارشی",jkSection:"زنجیره اینترنت خانگی",jkEnable:"فعال‌سازی زنجیره اینترنت خانگی",jkHint:n("2b7YsyDYp9iyINmB2LnYp9mE4oCM2LPYp9iy24zYjCDar9iy24zZhtmHIMKrQ0xBU0gg2K7Yp9mG2q/bjMK7INio2Ycg2YHZh9ix2LPYqiDaqdmE2KfbjNmG2KrigIzZh9inINin2LbYp9mB2Ycg2YXbjOKAjNi02YjYry4g2q/YsdmH4oCM2YfYp9uMIENGINmF2LPbjNixINix2Kcg2KjYp9iyINmF24zigIzaqdmG2YbYryDZiCDYrtix2YjYrNuMINin2LIg2KfbjNmG2KrYsdmG2Kog2K7Yp9mG2q/bjCDamNin2b7ZhtiMINqp2LHZhyDZiCDaqdi02YjYsdmH2KfbjCDYr9uM2q/YsSDYp9iz2KouINmB2YLYtyDZh9iz2KrZhyBDbGFzaCBNZXRhINmG2LPYrtmHIDEuMTkuMjUg2KjZhyDYqNin2YTYpyDYotmGINix2Kcg2YXbjOKAjNi02YbYp9iz2K/YmyBDbGFzaCBWZXJnZSBSZXbYjCBGbENsYXNoINmIIENNRkEg2qnYp9ixINmF24zigIzaqdmG2YbYry4g2q/YsdmH4oCM2YfYpyDYp9i02KrYsdin2qnbjCDZh9iz2KrZhtivINmIINqv2KfZh9uMINmC2LfYuSDZhduM4oCM2LTZiNmG2K/YjCDYp9i02KrYsdin2qkg2K7ZiNiv2LQg2q/YsdmHINiv24zar9ix24wg2LHYpyDYp9mG2KrYrtin2Kgg2YXbjOKAjNqp2YbYry4="),jkClient:"CLASH خانگی",allowAPIManagement:"اجازه مدیریت API (ae):",regionMatching:"تطبیق منطقه (rm):",downgradeControl:n("2LHZiNi0INiu2LHZiNisIChxaik6"),tlsControl:"کنترل TLS (dkby):",preferredControl:"کنترل ترجیحی (yxby):",saveAdvanced:"ذخیره تنظیمات پیشرفته",loading:"در حال بارگذاری...",currentConfig:"📍 پیکربندی مسیر فعلی",refreshConfig:"تازه‌سازی تنظیمات",resetConfig:"بازنشانی تنظیمات",subscriptionCopied:"لینک اشتراک کپی شد",autoSubscriptionCopied:"لینک اشتراک تشخیص خودکار کپی شد، کلاینت هنگام دسترسی بر اساس User-Agent به طور خودکار تشخیص داده و قالب مربوطه را برمی‌گرداند",altPasswordPlaceholder:"خالی بگذارید تا از UUID استفاده شود",altPasswordHint:n("2LHZhdiyINi52KjZiNixIFRyb2phbiDYs9mB2KfYsdi024wg2LHYpyDYqtmG2LjbjNmFINqp2YbbjNivLiDYp9qv2LEg2K7Yp9mE24wg2Kjar9iw2KfYsduM2K8g2KfYsiBVVUlEINin2LPYqtmB2KfYr9mHINmF24zigIzYtNmI2K8uINqp2YTYp9uM2YbYqiDYqNmHINi32YjYsSDYrtmI2K/aqdin2LEg2LHZhdiyINi52KjZiNixINix2Kcg2KjYpyBTSEEyMjQg2YfYtCDZhduM4oCM2qnZhtivLg=="),protocolHint:n("2YXbjOKAjNiq2YjYp9mG24zYryDahtmG2K/bjNmGINm+2LHZiNiq2qnZhCDYsdinINmH2YXYstmF2KfZhiDZgdi52KfZhCDaqdmG24zYry4g2KfYtNiq2LHYp9qpINqv2LHZh+KAjNmH2KfbjCDZvtix2YjYqtqp2YTigIzZh9in24wg2KfZhtiq2K7Yp9ioINi02K/ZhyDYsdinINiq2YjZhNuM2K8g2YXbjOKAjNqp2YbYry48YnI+4oCiIFZMRVNTIFdTOiDZvtix2YjYqtqp2YQg2KfYs9iq2KfZhtiv2KfYsdivINmF2KjYqtmG24wg2KjYsSBXZWJTb2NrZXQ8YnI+4oCiIFRyb2phbjog2KfYrdix2KfYsiDZh9mI24zYqiDYqNinINix2YXYsiDYudio2YjYsSBTSEEyMjQ8YnI+4oCiIHhodHRwOiDZvtix2YjYqtqp2YQg2KfYs9iq2KrYp9ixINmF2KjYqtmG24wg2KjYsSBIVFRQIFBPU1QgKNmG24zYp9iyINio2Ycg2KfYqti12KfZhCDYr9in2YXZhtmHINiz2YHYp9ix2LTbjCDZiCDZgdi52KfZhOKAjNiz2KfYstuMIGdSUEMg2K/Yp9ix2K8p"),alpn:"TLS ALPN",alpnDefault:"پیش‌فرض (خالی، مذاکره توسط کلاینت)",alpnHint:"فقط به لینک‌های TLS اضافه می‌شود؛ اگر خالی باشد alpn نوشته نمی‌شود.",saveProtocol:"ذخیره تنظیمات پروتکل",subscriptionConverterPlaceholder:"پیش‌فرض: https://url.v1.mk/sub",subscriptionConverterHint:"تبدیل اشتراک به صورت داخلی پیاده‌سازی شده است و نیازی به API خارجی ندارد. این فیلد فقط برای سازگاری حفظ شده و می‌توان آن را خالی گذاشت.",builtinPreferredHint:"کنترل اینکه کدام گره‌های ترجیحی داخلی در اشتراک گنجانده شوند. به طور پیش‌فرض همه فعال هستند.",apiEnabledDefault:"پیش‌فرض (بستن API)",apiEnabledYes:"فعال‌سازی مدیریت API",apiEnabledHint:"⚠️ هشدار امنیتی: فعال‌سازی این گزینه اجازه می‌دهد IP های ترجیحی از طریق API به طور پویا اضافه شوند. توصیه می‌شود فقط در صورت نیاز فعال کنید.",regionMatchingDefault:"پیش‌فرض (فعال‌سازی تطبیق منطقه)",regionMatchingNo:"بستن تطبیق منطقه",regionMatchingHint:'وقتی "بستن" تنظیم شود، تطبیق هوشمند منطقه انجام نمی‌شود',downgradeControlDefault:n("2KfZiNmE2YjbjNiqINio2Kcg2b7YsdmI2qnYs9uMICjZvtuM2LTigIzZgdix2LYp"),downgradeControlNo:n("2KfZiNmE2YjbjNiqINio2Kcg2KfYqti12KfZhCDZhdiz2KrZgtuM2YXYjCDYr9ixINi12YjYsdiqINiu2LfYpyDZvtix2Yjaqdiz24w="),downgradeControlOnly:n("2YHZgti3INm+2LHZiNqp2LPbjNiMINio2K/ZiNmGINio2KfYstqv2LTYqg=="),downgradeControlHint:n("2Kfar9ixINm+2LHZiNqp2LPbjCDYqtmG2LjbjNmFINmG2LTYr9mHINio2KfYtNivINmH2LEg2LPZhyDar9iy24zZhtmHINuM2qnYs9in2YYg2Ygg2YXYs9iq2YLbjNmFINmH2LPYqtmG2K8uINiv2LEg2K3Yp9mE2Kog2YHZgti3INm+2LHZiNqp2LPbjNiMINin2KrYtdin2YQg2YbYp9mF2YjZgdmCINmC2LfYuSDZhduM4oCM2LTZiNivINmIIElQINiu2LHZiNis24wg2YHYp9i0INmG2YXbjOKAjNi02YjYrw=="),tlsControlDefault:"پیش‌فرض (حفظ همه گره‌ها)",tlsControlYes:"فقط گره‌های TLS",tlsControlHint:'وقتی "فقط گره‌های TLS" تنظیم شود، فقط گره‌های با TLS تولید می‌شوند، گره‌های غیر TLS (مانند پورت 80) تولید نمی‌شوند',preferredControlDefault:"پیش‌فرض (فعال‌سازی ترجیح)",preferredControlYes:"بستن ترجیح",preferredControlHint:'وقتی "بستن ترجیح" تنظیم شود، فقط از آدرس اصلی استفاده می‌شود، گره‌های IP و دامنه ترجیحی تولید نمی‌شوند',regionNames:{CF:"🌐 مستقیم رسمی",HK:"🇭🇰 هنگ کنگ",US:"🇺🇸 آمریکا",SG:"🇸🇬 سنگاپور",JP:"🇯🇵 ژاپن",KR:"🇰🇷 کره جنوبی",DE:"🇩🇪 آلمان",SE:"🇸🇪 سوئد",NL:"🇳🇱 هلند",FI:"🇫🇮 فنلاند",GB:"🇬🇧 بریتانیا"},terminal:"ترمینال v3.1",githubProject:"پروژه GitHub",优选工具:"ابزار ترجیح IP",autoDetectClient:"تشخیص خودکار",selectionLogicText:"هم‌منطقه → منطقه مجاور → سایر مناطق",customIPDisabledHint:n("2YfZhtqv2KfZhSDYp9iz2KrZgdin2K/ZhyDYp9iyIFByb3h5SVAg2LPZgdin2LHYtNuM2Iwg2KfZhtiq2K7Yp9ioINmF2YbYt9mC2Ycg2LrbjNix2YHYudin2YQg2KfYs9iq"),customIPMode:n("2K3Yp9mE2KogUHJveHlJUCDYs9mB2KfYsdi024wgKNmF2KrYutuM2LEgcCDZgdi52KfZhCDYp9iz2Kop"),customIPModeDesc:"حالت IP سفارشی (تطبیق منطقه غیرفعال است)",usingCustomProxyIP:n("2KfYs9iq2YHYp9iv2Ycg2KfYsiBQcm94eUlQINiz2YHYp9ix2LTbjDog"),customIPConfig:" (پیکربندی متغیر p)",customIPModeDisabled:"حالت IP سفارشی، انتخاب منطقه غیرفعال است",manualRegion:"تعیین منطقه دستی",manualRegionDesc:" (تعیین دستی)",proxyIPAvailable:n("MTAvMTAg2K/YsSDYr9iz2KrYsdizICjYr9in2YXZhtmHINm+24zYtOKAjNmB2LHYtiBQcm94eUlQINiv2LEg2K/Ys9iq2LHYsyDYp9iz2Kop"),smartSelection:"انتخاب هوشمند نزدیک در حال انجام است",sameRegionIP:"IP هم‌منطقه در دسترس است (1)",cloudflareDetection:"اتصال مستقیم رسمی",detectionFailed:"تشخیص ناموفق",apiTestResult:"نتیجه تشخیص API: ",apiTestTime:"زمان تشخیص: ",apiTestFailed:"تشخیص API ناموفق: ",unknownError:"خطای ناشناخته",apiTestError:"تست API ناموفق: ",kvNotConfigured:"ذخیره‌سازی KV پیکربندی نشده است، نمی‌توانید از عملکرد مدیریت تنظیمات استفاده کنید.\\n\\nلطفا در Cloudflare Workers:\\n1. فضای نام KV ایجاد کنید\\n2. متغیر محیطی C را پیوند دهید\\n3. کد را دوباره مستقر کنید",kvNotEnabled:"ذخیره‌سازی KV پیکربندی نشده است",kvCheckFailed:"بررسی ذخیره‌سازی KV ناموفق: خطای فرمت پاسخ",kvCheckFailedStatus:"بررسی ذخیره‌سازی KV ناموفق - کد وضعیت: ",kvCheckFailedError:"بررسی ذخیره‌سازی KV ناموفق - خطا: "}}[a?"fa":"zh"],v=`<!DOCTYPE html>
    <html lang="${c}" dir="${a?"rtl":"ltr"}">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${r.title}</title>

    </head>
    <body>
        <header class="cp-topbar">
            <div class="cp-brand">
                <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><g stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M24 6.5v35"/><path d="M6.5 24h35"/><path d="M11.6 11.6l24.8 24.8"/><path d="M36.4 11.6L11.6 36.4"/><path d="M32.8 8.8L24 24"/><path d="M39.2 15.2L24 24"/><path d="M39.2 32.8L24 24"/><path d="M32.8 39.2L24 24"/><path d="M15.2 39.2L24 24"/><path d="M8.8 32.8L24 24"/><path d="M8.8 15.2L24 24"/><path d="M15.2 8.8L24 24"/></g></svg></span>
                <span class="cp-brand-name">CFnew</span>
            </div>
            <div class="cp-lang-wrapper">
                <select id="languageSelector" onchange="切换语言(this.value)" aria-label="${a?"زبان":"语言"}">
                    <option value="zh" ${a?"":"selected"}>中文</option>
                    <option value="fa" ${a?"selected":""}>فارسی</option>
                </select>
            </div>
        </header>
        <div class="container">
            <div class="header">
                    <div class="brand-mark brand-mark-lg" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><g stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M24 6.5v35"/><path d="M6.5 24h35"/><path d="M11.6 11.6l24.8 24.8"/><path d="M36.4 11.6L11.6 36.4"/><path d="M32.8 8.8L24 24"/><path d="M39.2 15.2L24 24"/><path d="M39.2 32.8L24 24"/><path d="M32.8 39.2L24 24"/><path d="M15.2 39.2L24 24"/><path d="M8.8 32.8L24 24"/><path d="M8.8 15.2L24 24"/><path d="M15.2 8.8L24 24"/></g></svg></div>
                    <h1 class="title" data-text="${r.title}">${r.title}</h1>
                    <p class="subtitle">${r.subtitle}</p>
            </div>
            <div class="card">
                    <h2 class="card-title">${r.selectClient}</h2>
                <div class="client-grid">
                    <button class="client-btn" onclick="生成客户端链接(atob('Y2xhc2g='), 'CLASH')">CLASH</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('Y2xhc2g='), 'STASH')">STASH</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('c3VyZ2U='), 'SURGE')">SURGE</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('c2luZ2JveA=='), 'SING-BOX')">SING-BOX</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('bG9vbg=='), 'LOON')">LOON</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('cXVhbng='), 'QUANTUMULT X')">QUANTUMULT X</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('djJyYXk='), 'V2RAY')">V2RAY</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('djJyYXk='), 'V2RAYNG')">V2RAYNG</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('djJyYXk='), 'NEKORAY')">NEKORAY</button>
                    <button class="client-btn" onclick="生成客户端链接(atob('djJyYXk='), 'Shadowrocket')">Shadowrocket</button>
                    <button class="client-btn" id="jkClientBtn" style="${he?"":"display: none;"}" onclick="生成客户端链接('vg', '${r.jkClient}')">${r.jkClient}</button>
                </div>
                <div class="subscription-url" id="clientSubscriptionUrl"></div>
            </div>
            <div class="card">
                    <h2 class="card-title">${r.systemStatus}</h2>
                <div id="systemStatus" style="margin: 20px 0; padding: 15px; background: var(--cp-surface-2); border: 2px solid var(--cp-border-strong);  position: relative; overflow: hidden;">
                        <div style="color: var(--cp-accent); margin-bottom: 15px; font-weight: bold; ">[ ${r.checking} ]</div>
                        <div id="regionStatus" style="margin: 8px 0; color: var(--cp-accent); font-family: var(--cp-font-mono); ">${r.workerRegion}${r.checking}</div>
                        <div id="geoInfo" style="margin: 8px 0; color: var(--cp-text-dim); font-family: var(--cp-font-mono); font-size: 0.9rem; ">${r.detectionMethod}${r.checking}</div>
                        <div id="backupStatus" style="margin: 8px 0; color: var(--cp-accent); font-family: var(--cp-font-mono); ">${r.proxyIPStatus}${r.checking}</div>
                        <div id="currentIP" style="margin: 8px 0; color: var(--cp-accent); font-family: var(--cp-font-mono); ">${r.currentIP}${r.checking}</div>
                        <div id="echStatus" style="margin: 8px 0; color: var(--cp-accent); font-family: var(--cp-font-mono);  font-size: 0.9rem;">ECH状态: ${r.checking}</div>
                        <div id="regionMatch" style="margin: 8px 0; color: var(--cp-accent); font-family: var(--cp-font-mono); ">${r.regionMatch}${r.checking}</div>
                        <div id="selectionLogic" style="margin: 8px 0; color: var(--cp-text-dim); font-family: var(--cp-font-mono); font-size: 0.9rem; ">${r.selectionLogic}${r.selectionLogicText}</div>
                </div>
            </div>
            <div class="card" id="configCard" style="display: none;">
                    <h2 class="card-title">${r.configManagement}</h2>
                <div id="kvStatus" style="margin-bottom: 20px; padding: 10px; background: var(--cp-surface-2); border: 1px solid var(--cp-border-strong); color: var(--cp-accent);">
                    ${r.kvStatusChecking}
                </div>
                <div id="configContent" style="display: none;">
                    <form id="regionForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.specifyRegion}</label>
                            <select id="wkRegion" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                    <option value="">${r.autoDetect}</option>
                                    <option value="HK">${r.regionNames.HK}</option>
                                    <option value="US">${r.regionNames.US}</option>
                                    <option value="SG">${r.regionNames.SG}</option>
                                    <option value="JP">${r.regionNames.JP}</option>
                                    <option value="KR">${r.regionNames.KR}</option>
                                    <option value="DE">${r.regionNames.DE}</option>
                                    <option value="SE">${r.regionNames.SE}</option>
                                    <option value="NL">${r.regionNames.NL}</option>
                                    <option value="FI">${r.regionNames.FI}</option>
                                    <option value="GB">${r.regionNames.GB}</option>
                            </select>
                                <small id="wkRegionHint" style="color: var(--cp-text-dim); font-size: 0.85rem; display: none;">⚠️ ${r.customIPDisabledHint}</small>
                        </div>
                    </form>
                    <form id="otherConfigForm" style="margin-bottom: 20px;">
                        <div class="cp-cpu-setting">
                            <label class="cp-cpu-switch" for="freeCpu">
                                <input type="checkbox" id="freeCpu" aria-describedby="freeCpuHint" ${Te?"":"disabled"}>
                                <span>Free CPU 保护</span>
                            </label>
                            <small id="freeCpuHint">${Te?"单连接上下载合计最多 384 KiB 或 96 个数据块，超过就断开。客户端需自行重连，下载和视频可能中断。保存后对新连接生效，不能保证零超限。":"当前内核不支持，请先更新配套内核。"}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.protocolSelection}</label>
                            <div style="padding: 15px; background: var(--cp-surface-2); border: 1px solid var(--cp-border-strong); border-radius: 5px;">
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                        <input type="checkbox" id="ev" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${r.enableProtoV}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                        <input type="checkbox" id="et" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${r.enableProtoT}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                        <input type="checkbox" id="ex" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${r.enableXhttp}</span>
                                    </label>
                                </div>
                                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--cp-border);">
                                    <div style="margin-bottom: 10px;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                            <input type="checkbox" id="ech" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                                <span style="font-size: 1.1rem;">${r.enableECH}</span>
                                        </label>
                                        <small style="color: var(--cp-text-dim); font-size: 0.8rem; display: block; margin-top: 5px; margin-left: 26px;">${r.enableECHHint}</small>
                                    </div>
                                    <div style="margin-top: 15px; margin-bottom: 10px;">
                                        <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-size: 0.95rem;">${r.customDNS}</label>
                                        <input type="text" id="customDNS" placeholder="${r.customDNSPlaceholder}" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                        <small style="color: var(--cp-text-dim); font-size: 0.8rem; display: block; margin-top: 5px;">${r.customDNSHint}</small>
                                    </div>
                                    <div style="margin-bottom: 10px;">
                                        <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-size: 0.95rem;">${r.customECHDomain}</label>
                                        <input type="text" id="customECHDomain" placeholder="${r.customECHDomainPlaceholder}" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                        <small style="color: var(--cp-text-dim); font-size: 0.8rem; display: block; margin-top: 5px;">${r.customECHDomainHint}</small>
                                    </div>
                                    <div style="margin-bottom: 10px;">
                                        <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-size: 0.95rem;">${r.alpn}</label>
                                        <select id="alpn" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                            <option value="">${r.alpnDefault}</option>
                                            <option value="h3">h3</option>
                                            <option value="h2">h2</option>
                                            <option value="http/1.1">http/1.1</option>
                                            <option value="h3,h2">h3,h2</option>
                                            <option value="h2,http/1.1">h2,http/1.1</option>
                                            <option value="h3,h2,http/1.1">h3,h2,http/1.1</option>
                                        </select>
                                        <small style="color: var(--cp-text-dim); font-size: 0.8rem; display: block; margin-top: 5px;">${r.alpnHint}</small>
                                    </div>
                                </div>
                                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--cp-border);">
                                        <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-size: 0.95rem;">${r.altPassword}</label>
                                        <input type="text" id="tp" placeholder="${r.altPasswordPlaceholder}" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                        <small style="color: var(--cp-text-dim); font-size: 0.8rem; display: block; margin-top: 5px;">${r.altPasswordHint}</small>
                                </div>
                                    <small style="color: var(--cp-text-dim); font-size: 0.85rem; display: block; margin-top: 10px;">${r.protocolHint}</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.customHomepage}</label>
                                <input type="text" id="customHomepage" placeholder="${r.customHomepagePlaceholder}" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${r.customHomepageHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.customPath}</label>
                                <input type="text" id="customPath" placeholder="${a?"مثال: /mypath یا خالی بگذارید تا از UUID استفاده شود":"例如: /mypath 或留空使用 UUID"}" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${n(a?"2YXYs9uM2LEg2KfYtNiq2LHYp9qpINiz2YHYp9ix2LTbjC4g2Kfar9ixINiu2KfZhNuMINio2q/YsNin2LHbjNivINin2LIgVVVJRCDYqNmHINi52YbZiNin2YYg2YXYs9uM2LEg2KfYs9iq2YHYp9iv2Ycg2YXbjOKAjNi02YjYry4=":"6Ieq5a6a5LmJ6K6i6ZiF6Lev5b6E44CC55WZ56m65YiZ5L2/55SoIFVVSUQg5L2c5Li66Lev5b6E44CC")}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.customIP}</label>
                                <input type="text" id="customIP" placeholder="${a?"مثال: 1.2.3.4:443":"例如: 1.2.3.4:443"}" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${n(a?"2KLYr9ix2LMg2Ygg2b7ZiNix2KogUHJveHlJUCDYs9mB2KfYsdi024w=":"6Ieq5a6a5LmJUHJveHlJUOWcsOWdgOWSjOerr+WPow==")}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.preferredIPs}</label>
                                <textarea id="yx" rows="8" spellcheck="false" placeholder="104.16.1.1:443#日本节点&#10;[2606:4700::1111]:443#IPv6节点&#10;example.com:8443#域名节点" style="width: 100%; min-height: 180px; resize: vertical; line-height: 1.6; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;"></textarea>
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${a?'فرمت: IP:پورت#نام گره یا IP:پورت (بدون # از نام پیش‌فرض استفاده می‌شود). پشتیبانی از چندین مورد، با خط جدید یا کاما جدا می‌شوند. <span style="color: var(--cp-warning);">IP های اضافه شده از طریق API به طور خودکار در اینجا نمایش داده می‌شوند.</span>':'格式: IP:端口#节点名称 或 IP:端口 (无#则使用默认名称)。每行一个，也支持英文逗号分隔。<span style="color: var(--cp-warning);">API添加的IP会自动显示在这里。</span>'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.preferredIPsURL}</label>
                                <input type="text" id="yxURL" placeholder="${a?"URL منبع لیست IP ترجیحی را وارد کنید":"输入优选IP列表来源URL"}" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${a?"URL منبع لیست IP ترجیحی سفارشی، اگر خالی بگذارید از آدرس پیش‌فرض استفاده می‌شود":"自定义优选IP列表来源URL，留空则使用默认地址"}</small>
                        </div>
                        
                        <div style="margin-bottom: 20px; padding: 15px; background: var(--cp-surface-2); border: 2px solid var(--cp-border-strong); border-radius: 8px;">
                            <h4 style="color: var(--cp-accent); margin: 0 0 15px 0; font-size: 1.1rem; ">⚡ ${r.latencyTest}</h4><small style="color:var(--cp-text-dim)">检测可用性；延迟按面板服务器位置测得。</small>
                            <div style="display: flex; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; align-items: center;">
                                <div style="min-width: 120px;">
                                    <label style="display: block; margin-bottom: 5px; color: var(--cp-accent); font-size: 0.9rem;">${r.ipSource}</label>
                                    <select id="ipSourceSelect" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px; cursor: pointer;">
                                        <option value="manual">${r.manualInput}</option>
                                        <option value="cfRandom">${r.cfRandomIP}</option>
                                        <option value="urlFetch">${r.urlFetch}</option>
                                    </select>
                                </div>
                                <div style="width: 100px;">
                                    <label style="display: block; margin-bottom: 5px; color: var(--cp-accent); font-size: 0.9rem;">${r.latencyTestPort}</label>
                                    <input type="number" id="latencyTestPort" value="443" min="1" max="65535" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                </div>
                                <div id="randomCountDiv" style="width: 100px; display: none;">
                                    <label style="display: block; margin-bottom: 5px; color: var(--cp-accent); font-size: 0.9rem;">${r.randomCount}</label>
                                    <input type="number" id="randomIPCount" value="20" min="1" max="100" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                </div>
                                <div style="width: 80px;">
                                    <label style="display: block; margin-bottom: 5px; color: var(--cp-accent); font-size: 0.9rem;">${a?"رشته‌ها":"线程"}</label>
                                    <input type="number" id="testThreads" value="5" min="1" max="50" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                </div>
                            </div>
                            <div id="manualInputDiv" style="margin-bottom: 10px;">
                                <label style="display: block; margin-bottom: 5px; color: var(--cp-accent); font-size: 0.9rem;">${r.latencyTestIP}</label>
                                <input type="text" id="latencyTestInput" placeholder="${r.latencyTestIPPlaceholder}" style="width: 100%; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                            </div>
                            <div id="urlFetchDiv" style="margin-bottom: 10px; display: none;">
                                <label style="display: block; margin-bottom: 5px; color: var(--cp-accent); font-size: 0.9rem;">${r.fetchURL}</label>
                                <div style="display: flex; gap: 8px;">
                                    <input type="text" id="fetchURLInput" placeholder="${r.fetchURLPlaceholder}" style="flex: 1; padding: 10px; background: var(--cp-field); border: 1px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 13px;">
                                    <button type="button" id="fetchIPBtn" style="background: var(--cp-accent-soft); border: 1px solid var(--cp-border-strong); padding: 8px 16px; color: var(--cp-accent); font-family: var(--cp-font-mono); cursor: pointer; white-space: nowrap;">⬇ ${r.fetchIP}</button>
                                </div>
                            </div>
                            <div id="cfRandomDiv" style="margin-bottom: 10px; display: none;">
                                <button type="button" id="generateCFIPBtn" style="background: var(--cp-accent-soft); border: 1px solid var(--cp-border-strong); padding: 10px 20px; color: var(--cp-accent); font-family: var(--cp-font-mono); cursor: pointer; width: 100%; transition: all 0.3s;">🎲 ${r.generateIP}</button>
                            </div>
                            <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                                <button type="button" id="startLatencyTest" style="background: var(--cp-accent-soft); border: 1px solid var(--cp-border-strong); padding: 8px 16px; color: var(--cp-accent); font-family: var(--cp-font-mono); cursor: pointer; transition: all 0.3s;">▶ ${r.startTest}</button>
                                <button type="button" id="stopLatencyTest" style="background: var(--cp-danger-soft); border: 1px solid var(--cp-danger); padding: 8px 16px; color: var(--cp-danger); font-family: var(--cp-font-mono); cursor: pointer; display: none; transition: all 0.3s;">⏹ ${r.stopTest}</button>
                            </div>
                            <div id="latencyTestStatus" style="color: var(--cp-text-dim); font-size: 0.9rem; margin-bottom: 10px; display: none;"></div>
                            <div id="latencyTestResults" style="max-height: 250px; overflow-y: auto; display: none;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                    <span style="color: var(--cp-accent); font-weight: bold;">${r.testResult}</span>
                                    <div style="display: flex; gap: 8px;">
                                        <button type="button" id="selectAllResults" style="background: transparent; border: 1px solid var(--cp-border); padding: 4px 10px; color: var(--cp-text-dim); font-size: 0.8rem; cursor: pointer;">${r.selectAll}</button>
                                        <button type="button" id="deselectAllResults" style="background: transparent; border: 1px solid var(--cp-border); padding: 4px 10px; color: var(--cp-text-dim); font-size: 0.8rem; cursor: pointer;">${r.deselectAll}</button>
                                    </div>
                                </div>
                                <div id="cityFilterContainer" style="margin-bottom: 10px; padding: 10px; background: var(--cp-surface-2); border: 1px solid var(--cp-border); border-radius: 4px; display: none;">
                                    <div style="margin-bottom: 8px;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent); font-size: 0.9rem;">
                                            <input type="radio" name="cityFilterMode" value="all" checked style="margin-right: 6px; width: 16px; height: 16px; cursor: pointer;">
                                            <span>全部城市</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent); font-size: 0.9rem; margin-left: 15px;">
                                            <input type="radio" name="cityFilterMode" value="fastest10" style="margin-right: 6px; width: 16px; height: 16px; cursor: pointer;">
                                            <span>只选择最快的10个</span>
                                        </label>
                                    </div>
                                    <div id="cityCheckboxesContainer" style="display: flex; flex-wrap: wrap; gap: 8px; max-height: 80px; overflow-y: auto; padding: 5px;"></div>
                                </div>
                                <div id="latencyResultsList" style="background: var(--cp-surface-2); border: 1px solid var(--cp-border); border-radius: 4px; padding: 10px;"></div>
                                <div style="margin-top: 10px; display: flex; gap: 10px;">
                                    <button type="button" id="overwriteSelectedToYx" style="flex: 1; background: var(--cp-accent-soft); border: 1px solid var(--cp-border-strong); padding: 10px 20px; color: var(--cp-accent); font-family: var(--cp-font-mono); font-weight: bold; cursor: pointer; transition: all 0.3s;">覆盖添加</button>
                                    <button type="button" id="appendSelectedToYx" style="flex: 1; background: var(--cp-surface-2); border: 1px solid var(--cp-border); padding: 10px 20px; color: var(--cp-text-dim); font-family: var(--cp-font-mono); font-weight: bold; cursor: pointer; transition: all 0.3s;">追加添加</button>
                                </div>
                            </div>
                        </div>

                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.socks5Config}</label>
                                <input type="text" id="socksConfig" placeholder="${n(a?"2YXYq9in2YQ6IHVzZXI6cGFzc0Bob3N0OnBvcnQg24zYpyBodHRwOi8vdXNlcjpwYXNzQGhvc3Q6cG9ydA==":"5L6L5aaCOiB1c2VyOnBhc3NAaG9zdDpwb3J0IOaIliBodHRwOi8vdXNlcjpwYXNzQGhvc3Q6cG9ydA==")}" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${n(a?"2KLYr9ix2LMg2b7YsdmI2qnYs9uMINiu2LHZiNis24wg2KjYsdin24wg2KfZhtiq2YLYp9mEINiq2YXYp9mFINiq2LHYp9mB24zaqSDYrtix2YjYrNuMLiDYqNiv2YjZhiDZvtuM2LTZiNmG2K8g2KjZhyDYtdmI2LHYqiBzNSDYr9ixINmG2LjYsSDar9ix2YHYqtmHINmF24zigIzYtNmI2K8=":"5Ye656uZ5Luj55CG5Zyw5Z2A77yM55So5LqO6L2s5Y+R5omA5pyJ5Ye656uZ5rWB6YeP44CC5LiN5YaZ5YmN57yA6buY6K6k5oyJIHM1IOWkhOeQhg==")}</small>
                        </div>
                    </form>

                    <h3 style="color: var(--cp-accent); margin: 20px 0 15px 0; font-size: 1.2rem;">${r.advancedControl}</h3>
                    <form id="advancedConfigForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.subscriptionConverter}</label>
                                <input type="text" id="scu" placeholder="${r.subscriptionConverterPlaceholder}" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${r.subscriptionConverterHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.builtinPreferred}</label>
                            <div style="padding: 15px; background: var(--cp-surface-2); border: 1px solid var(--cp-border-strong); border-radius: 5px;">
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                        <input type="checkbox" id="ena" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${r.enableNativeAddress}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                        <input type="checkbox" id="epd" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${r.enablePreferredDomain}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                        <input type="checkbox" id="epi" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${r.enablePreferredIP}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                        <input type="checkbox" id="egi" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${r.enableGitHubPreferred}</span>
                                    </label>
                                </div>
                                    <small style="color: var(--cp-text-dim); font-size: 0.85rem; display: block; margin-top: 10px;">${r.builtinPreferredHint}</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.jkSection}</label>
                            <div style="padding: 15px; background: var(--cp-surface-2); border: 1px solid var(--cp-border-strong); border-radius: 5px;">
                                <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                    <input type="checkbox" id="jk" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                        <span style="font-size: 1.1rem;">${r.jkEnable}</span>
                                </label>
                                    <small style="color: var(--cp-text-dim); font-size: 0.85rem; display: block; margin-top: 10px;">${r.jkHint}</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">优选IP筛选设置</label>
                            <div style="padding: 15px; background: var(--cp-surface-2); border: 1px solid var(--cp-border-strong); border-radius: 5px;">
                                <div style="margin-bottom: 15px;">
                                    <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">IP版本选择</label>
                                    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                            <input type="checkbox" id="ipv4Enabled" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">IPv4</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                            <input type="checkbox" id="ipv6Enabled" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">IPv6</span>
                                        </label>
                                    </div>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">运营商选择</label>
                                    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                            <input type="checkbox" id="ispMobile" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">移动</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                            <input type="checkbox" id="ispUnicom" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">联通</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent);">
                                            <input type="checkbox" id="ispTelecom" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">电信</span>
                                        </label>
                                    </div>
                                </div>
                                    <small style="color: var(--cp-text-dim); font-size: 0.85rem; display: block; margin-top: 10px;">选择要使用的IP版本和运营商，未选中的将被过滤</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.allowAPIManagement}</label>
                            <select id="apiEnabled" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                    <option value="">${r.apiEnabledDefault}</option>
                                    <option value="yes">${r.apiEnabledYes}</option>
                            </select>
                                <small style="color: var(--cp-warning); font-size: 0.85rem;">${r.apiEnabledHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.regionMatching}</label>
                            <select id="regionMatching" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                    <option value="">${r.regionMatchingDefault}</option>
                                    <option value="no">${r.regionMatchingNo}</option>
                            </select>
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${r.regionMatchingHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.downgradeControl}</label>
                            <select id="downgradeControl" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                    <option value="">${r.downgradeControlDefault}</option>
                                    <option value="no">${r.downgradeControlNo}</option>
                                    <option value="only">${r.downgradeControlOnly}</option>
                            </select>
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${r.downgradeControlHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.tlsControl}</label>
                            <select id="portControl" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                    <option value="">${r.tlsControlDefault}</option>
                                    <option value="yes">${r.tlsControlYes}</option>
                            </select>
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${r.tlsControlHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: var(--cp-accent); font-weight: bold; ">${r.preferredControl}</label>
                            <select id="preferredControl" style="width: 100%; padding: 12px; background: var(--cp-field); border: 2px solid var(--cp-border-strong); color: var(--cp-accent); font-family: var(--cp-font-mono); font-size: 14px;">
                                    <option value="">${r.preferredControlDefault}</option>
                                    <option value="yes">${r.preferredControlYes}</option>
                            </select>
                                <small style="color: var(--cp-text-dim); font-size: 0.85rem;">${r.preferredControlHint}</small>
                        </div>
                    </form>
                    <div id="currentConfig" style="background: var(--cp-field); border: 1px solid var(--cp-border-strong); padding: 15px; margin: 10px 0; font-family: var(--cp-font-mono); color: var(--cp-accent);">
                            ${r.loading}
                    </div>
                    <div id="pathTypeInfo" style="background: var(--cp-surface-2); border: 1px solid var(--cp-border-strong); padding: 15px; margin: 10px 0; font-family: var(--cp-font-mono); color: var(--cp-accent);">
                            <div style="font-weight: bold; margin-bottom: 8px; color: var(--cp-success); ">${r.currentConfig}</div>
                            <div id="pathTypeStatus">${r.checking}</div>
                    </div>
                </div>
                <div id="statusMessage" style="display: none; padding: 10px; margin: 10px 0; border: 1px solid var(--cp-border-strong); background: var(--cp-surface-2); color: var(--cp-accent); "></div>
            </div>
            
            <div class="card">
                    <h2 class="card-title">${r.relatedLinks}</h2>
                <div style="text-align: center; margin: 20px 0;">
                        <a href="https://github.com/byJoey/cfnew" target="_blank" style="color: var(--cp-accent); text-decoration: none; margin: 0 20px; font-size: 1.2rem; ">${r.githubProject}</a>
                        <a href="https://github.com/byJoey/yx-tools/releases/" target="_blank" rel="noopener noreferrer" style="color: var(--cp-accent); text-decoration: none; margin: 0 20px; font-size: 1.2rem; ">${r.优选工具}</a>
                    <a href="https://www.youtube.com/@joeyblog" target="_blank" style="color: var(--cp-accent); text-decoration: none; margin: 0 20px; font-size: 1.2rem; ">YouTube @joeyblog</a>
                </div>
            </div>
        </div>
        <div id="cpToastStack" class="cp-toast-stack" aria-live="polite" aria-atomic="false"></div>
        <div id="cpActionStatus" class="cp-action-status" role="status" aria-live="polite"></div>
        <div id="cpActionBar" class="cp-action-bar" role="toolbar" aria-label="${r.configManagement}">
            <button type="button" id="cpBtnSaveAll" class="cp-fab-save" title="${a?"ذخیره همه تنظیمات":"保存所有配置 (Ctrl+S)"}">
                <span class="cp-fab-icon">▣</span>
                <span>${a?"ذخیره همه":"保 存 全 部"}</span>
                <span class="cp-fab-dot" aria-hidden="true"></span>
            </button>
            <button type="button" id="cpBtnRefresh" class="cp-action-btn" data-tip="${r.refreshConfig}" aria-label="${r.refreshConfig}">
                <span aria-hidden="true">↻</span>
                <span class="cp-btn-label">${r.refreshConfig}</span>
            </button>
            <button type="button" id="cpBtnReset" class="cp-action-btn cp-action-btn-danger" data-tip="${r.resetConfig}" aria-label="${r.resetConfig}">
                <span aria-hidden="true">⌫</span>
                <span class="cp-btn-label">${r.resetConfig}</span>
            </button>
        </div>
        <script>
// 地址从服务器配置注入
var 订阅转换网址 = ${JSON.stringify(Ne).replaceAll("<","\\u003c")};
// 远程配置URL（硬编码）
var 远程配置网址 = "${ct}";

// 翻译对象
const 本地值20215 = {
  zh: {
    subscriptionCopied: '${n("6K6i6ZiF6ZO+5o6l5bey5aSN5Yi2")}',
    autoSubscriptionCopied: '${n("6Ieq5Yqo6K+G5Yir6K6i6ZiF6ZO+5o6l5bey5aSN5Yi277yM5a6i5oi356uv6K6/6Zeu5pe25Lya5qC55o2uVXNlci1BZ2VudOiHquWKqOivhuWIq+W5tui/lOWbnuWvueW6lOagvOW8jw==")}'
  },
  fa: {
    subscriptionCopied: 'لینک اشتراک کپی شد',
    autoSubscriptionCopied: 'لینک اشتراک تشخیص خودکار کپی شد، کلاینت هنگام دسترسی بر اساس User-Agent به طور خودکار تشخیص داده و قالب مربوطه را برمی‌گرداند'
  }
};
async function 请求优选操作(动作, 数据, 信号) {
  return fetch((window.CFNEW.preferredApiBase || location.origin) + '/api/preferred/' + 动作, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host: window.CFNEW.host, uuid: window.CFNEW.uuid, ...数据 }), signal: 信号
  });
}
function 获取凭据20214(名称20213) {
  const 值20212 = '; ' + document.cookie;
  const 部分列表20211 = 值20212.split('; ' + 名称20213 + '=');
  if (部分列表20211.length === 2) return 部分列表20211.pop().split(';').shift();
  return null;
}
const 浏览器语言20210 = navigator.language || navigator.userLanguage || '';
const 已保存语言20209 = localStorage.getItem('preferredLanguage') || 获取凭据20214('preferredLanguage');
let 是否值20208 = false;
if (已保存语言20209 === 'fa' || 已保存语言20209 === 'fa-IR') {
  是否值20208 = true;
} else if (已保存语言20209 === 'zh' || 已保存语言20209 === 'zh-CN') {
  是否值20208 = false;
} else {
  是否值20208 = 浏览器语言20210.includes('fa') || 浏览器语言20210.includes('fa-IR');
}
const 翻译值20207 = 本地值20215[是否值20208 ? 'fa' : 'zh'];
function 切换语言(语言) {
  localStorage.setItem('preferredLanguage', 语言);
  // 设置Cookie（有效期1年）
  const 过期日期20206 = new Date();
  过期日期20206.setFullYear(过期日期20206.getFullYear() + 1);
  document.cookie = 'preferredLanguage=' + 语言 + '; path=/; expires=' + 过期日期20206.toUTCString() + '; SameSite=Lax';
  // 刷新页面，不使用URL参数
  window.location.reload();
}

// 页面加载时检查 localStorage 和 Cookie，并清理URL参数
window.addEventListener('DOMContentLoaded', function () {
  const 已保存语言20205 = localStorage.getItem('preferredLanguage') || 获取凭据20214('preferredLanguage');
  const 网址参数 = new URLSearchParams(window.location.search);
  const 网址语言 = 网址参数.get('lang');

  // 如果URL中有语言参数，移除它并设置Cookie
  if (网址语言) {
    const 当前网址20204 = new URL(window.location.href);
    当前网址20204.searchParams.delete('lang');
    const 新网址 = 当前网址20204.toString();

    // 设置Cookie
    const 过期日期20203 = new Date();
    过期日期20203.setFullYear(过期日期20203.getFullYear() + 1);
    document.cookie = 'preferredLanguage=' + 网址语言 + '; path=/; expires=' + 过期日期20203.toUTCString() + '; SameSite=Lax';
    localStorage.setItem('preferredLanguage', 网址语言);

    // 使用history API移除URL参数，不刷新页面
    window.history.replaceState({}, '', 新网址);
  } else if (已保存语言20205) {
    // 如果localStorage中有但Cookie中没有，同步到Cookie
    const 过期日期 = new Date();
    过期日期.setFullYear(过期日期.getFullYear() + 1);
    document.cookie = 'preferredLanguage=' + 已保存语言20205 + '; path=/; expires=' + 过期日期.toUTCString() + '; SameSite=Lax';
  }
});

// 赛博朋克风 toast 通知 (替代 alert)
window.显示提示 = function (消息20202, 类型20201, 本地值20200) {
  本地值20200 = 本地值20200 || {};
  var 堆栈 = document.getElementById('cpToastStack');
  if (!堆栈) return;
  var 类型映射 = {
    success: '✓',
    info: '⌬',
    warn: '⚠',
    error: '✕'
  };
  var 标题映射 = {
    success: 'SUCCESS',
    info: 'INFO',
    warn: 'WARN',
    error: 'ERROR'
  };
  类型20201 = 类型映射[类型20201] ? 类型20201 : 'success';
  var 持续时间 = 本地值20200.duration || 3200;
  var 提示 = document.createElement('div');
  提示.className = 'cp-toast cp-toast-' + 类型20201;
  提示.style.setProperty('--cp-toast-dur', 持续时间 + 'ms');
  var 图标 = document.createElement('span');
  图标.className = 'cp-toast-icon';
  图标.textContent = 类型映射[类型20201];
  var 主体 = document.createElement('div');
  主体.className = 'cp-toast-body';
  var 标题 = document.createElement('div');
  标题.className = 'cp-toast-title';
  标题.textContent = 本地值20200.title || 标题映射[类型20201];
  var 消息20199 = document.createElement('div');
  消息20199.className = 'cp-toast-msg';
  消息20199.textContent = String(消息20202 == null ? '' : 消息20202);
  主体.appendChild(标题);
  主体.appendChild(消息20199);
  var 关闭 = document.createElement('button');
  关闭.type = 'button';
  关闭.className = 'cp-toast-close';
  关闭.setAttribute('aria-label', 'close');
  关闭.textContent = '✕';
  提示.appendChild(图标);
  提示.appendChild(主体);
  提示.appendChild(关闭);
  堆栈.appendChild(提示);
  requestAnimationFrame(function () {
    提示.classList.add('cp-show');
  });
  var 本地值20198 = false;
  function 关闭提示() {
    if (本地值20198) return;
    本地值20198 = true;
    提示.classList.remove('cp-show');
    提示.classList.add('cp-hide');
    setTimeout(function () {
      if (提示.parentNode) 提示.parentNode.removeChild(提示);
    }, 400);
  }
  关闭.addEventListener('click', 关闭提示);
  var 计时器 = setTimeout(关闭提示, 持续时间);
  提示.addEventListener('mouseenter', function () {
    clearTimeout(计时器);
  });
  提示.addEventListener('mouseleave', function () {
    计时器 = setTimeout(关闭提示, 1200);
  });
  return {
    dismiss: 关闭提示,
    element: 提示
  };
};
function 尝试打开应用(方案网址20197, 回退回调, 超时20196) {
  超时20196 = 超时20196 || 2500;
  var 应用已打开 = false;
  var 回调已执行 = false;
  var 开始值 = Date.now();
  var 值值20195 = function () {
    var 耗时20194 = Date.now() - 开始值;
    if (耗时20194 < 3000 && !回调已执行) {
      应用已打开 = true;
    }
  };
  window.addEventListener('blur', 值值20195);
  var 值值20193 = function () {
    var 耗时 = Date.now() - 开始值;
    if (耗时 < 3000 && !回调已执行) {
      应用已打开 = true;
    }
  };
  document.addEventListener('visibilitychange', 值值20193);
  var 内嵌框架 = document.createElement('iframe');
  内嵌框架.style.display = 'none';
  内嵌框架.style.width = '1px';
  内嵌框架.style.height = '1px';
  内嵌框架.src = 方案网址20197;
  document.body.appendChild(内嵌框架);
  setTimeout(function () {
    内嵌框架.parentNode && 内嵌框架.parentNode.removeChild(内嵌框架);
    window.removeEventListener('blur', 值值20195);
    document.removeEventListener('visibilitychange', 值值20193);
    if (!回调已执行) {
      回调已执行 = true;
      if (!应用已打开 && 回退回调) {
        回退回调();
      }
    }
  }, 超时20196);
}
function 生成客户端链接(客户端类型, 客户端名称) {
  var 当前网址20192 = window.location.href;
  var 订阅网址20191 = window.CFNEW.subUrl;
  var 方案网址 = '';
  var 显示名称 = 客户端名称 || '';
  var 最终网址 = 订阅网址20191;
  if (客户端类型 === atob('djJyYXk=')) {
    最终网址 = 订阅网址20191;
    var 网址值20190 = document.getElementById("clientSubscriptionUrl");
    网址值20190.textContent = 最终网址;
    网址值20190.style.display = "block";
    网址值20190.style.overflowWrap = "break-word";
    网址值20190.style.wordBreak = "break-all";
    网址值20190.style.overflowX = "auto";
    网址值20190.style.maxWidth = "100%";
    网址值20190.style.boxSizing = "border-box";
    if (客户端名称 === 'V2RAY') {
      navigator.clipboard.writeText(最终网址).then(function () {
        显示提示(显示名称 + " " + 翻译值20207.subscriptionCopied, 'success');
      });
    } else if (客户端名称 === 'Shadowrocket') {
      方案网址 = '${n("c2hhZG93cm9ja2V0Oi8vYWRkLw==")}' + encodeURIComponent(最终网址);
      尝试打开应用(方案网址, function () {
        navigator.clipboard.writeText(最终网址).then(function () {
          显示提示(显示名称 + " " + 翻译值20207.subscriptionCopied, 'success');
        });
      });
    } else if (客户端名称 === 'V2RAYNG') {
      方案网址 = '${n("djJyYXluZzovL2luc3RhbGw/dXJsPQ==")}' + encodeURIComponent(最终网址);
      尝试打开应用(方案网址, function () {
        navigator.clipboard.writeText(最终网址).then(function () {
          显示提示(显示名称 + " " + 翻译值20207.subscriptionCopied, 'success');
        });
      });
    } else if (客户端名称 === 'NEKORAY') {
      方案网址 = '${n("bmVrb3JheTovL2luc3RhbGwtY29uZmlnP3VybD0=")}' + encodeURIComponent(最终网址);
      尝试打开应用(方案网址, function () {
        navigator.clipboard.writeText(最终网址).then(function () {
          显示提示(显示名称 + " " + 翻译值20207.subscriptionCopied, 'success');
        });
      });
    }
  } else {
    // 统一走内部格式转换
    最终网址 = 订阅网址20191 + (订阅网址20191.includes('?') ? '&' : '?') + "target=" + 客户端类型;
    var 网址值20190 = document.getElementById("clientSubscriptionUrl");
    网址值20190.textContent = 最终网址;
    网址值20190.style.display = "block";
    网址值20190.style.overflowWrap = "break-word";
    网址值20190.style.wordBreak = "break-all";
    网址值20190.style.overflowX = "auto";
    网址值20190.style.maxWidth = "100%";
    网址值20190.style.boxSizing = "border-box";
    if (客户端类型 === 'vg') {
      方案网址 = '${n("Y2xhc2g6Ly9pbnN0YWxsLWNvbmZpZz91cmw9")}' + encodeURIComponent(最终网址);
    } else if (客户端类型 === atob('Y2xhc2g=')) {
      if (客户端名称 === 'STASH') {
        方案网址 = '${n("c3Rhc2g6Ly9pbnN0YWxsP3VybD0=")}' + encodeURIComponent(最终网址);
        显示名称 = 'STASH';
      } else {
        方案网址 = '${n("Y2xhc2g6Ly9pbnN0YWxsLWNvbmZpZz91cmw9")}' + encodeURIComponent(最终网址);
        显示名称 = 'CLASH';
      }
    } else if (客户端类型 === atob('c3VyZ2U=')) {
      方案网址 = '${n("c3VyZ2U6Ly8vaW5zdGFsbC1jb25maWc/dXJsPQ==")}' + encodeURIComponent(最终网址);
      显示名称 = 'SURGE';
    } else if (客户端类型 === atob('c2luZ2JveA==')) {
      方案网址 = '${n("c2luZy1ib3g6Ly9pbnN0YWxsLWNvbmZpZz91cmw9")}' + encodeURIComponent(最终网址);
      显示名称 = 'SING-BOX';
    } else if (客户端类型 === atob('bG9vbg==')) {
      方案网址 = '${n("bG9vbjovL2luc3RhbGw/dXJsPQ==")}' + encodeURIComponent(最终网址);
      显示名称 = 'LOON';
    } else if (客户端类型 === atob('cXVhbng=')) {
      方案网址 = '${n("cXVhbnR1bXVsdC14Oi8vaW5zdGFsbC1jb25maWc/dXJsPQ==")}' + encodeURIComponent(最终网址);
      显示名称 = 'QUANTUMULT X';
    }
    if (方案网址) {
      尝试打开应用(方案网址, function () {
        navigator.clipboard.writeText(最终网址).then(function () {
          显示提示(显示名称 + " " + 翻译值20207.subscriptionCopied, 'success');
        });
      });
    } else {
      navigator.clipboard.writeText(最终网址).then(function () {
        显示提示(显示名称 + " " + 翻译值20207.subscriptionCopied, 'success');
      });
    }
  }
}

// 页面特效图形化开关 (localStorage 持久化)
window.应用页面特效 = function () {
  var 本地值20189 = localStorage.getItem('cp-fx-off') === '1';
  document.body.classList.toggle('fx-off', 本地值20189);
  var 本地值20188 = document.getElementById('cpFxLabel');
  if (本地值20188) 本地值20188.textContent = 本地值20189 ? 'FX: OFF' : 'FX: ON';
  if (本地值20189) {
    var 本地值20187 = document.getElementById('matrixCodeRain');
    if (本地值20187) 本地值20187.innerHTML = '';
  } else if (typeof 创建矩阵雨 === 'function') {
    var 结果值 = document.getElementById('matrixCodeRain');
    if (结果值 && !结果值.firstChild) 创建矩阵雨();
  }
};
window.切换页面特效 = function () {
  var 本地值20186 = localStorage.getItem('cp-fx-off') === '1';
  localStorage.setItem('cp-fx-off', 本地值20186 ? '0' : '1');
  window.应用页面特效();
};
(function () {
  if (localStorage.getItem('cp-fx-off') === '1') {
    document.addEventListener('DOMContentLoaded', function () {
      document.body.classList.add('fx-off');
      var 本地值20185 = document.getElementById('cpFxLabel');
      if (本地值20185) 本地值20185.textContent = 'FX: OFF';
    });
  }
})();
function 创建矩阵雨() {
  if (document.body && document.body.classList.contains('fx-off')) return;
  const 矩阵值 = document.getElementById('matrixCodeRain');
  if (!矩阵值) return;
  const 赛博字符列表 = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ$%#@!?<>+=ABCDEF';
  const 调色板 = ['var(--cp-accent)', 'var(--cp-accent-dark)', 'var(--cp-accent-dark)', 'var(--cp-success)'];
  const 列数 = Math.floor(window.innerWidth / 20);
  for (let 索引值20184 = 0; 索引值20184 < 列数; 索引值20184++) {
    const 列20183 = document.createElement('div');
    列20183.className = 'matrix-column';
    列20183.style.left = 索引值20184 * 20 + 'px';
    列20183.style.animationDelay = -Math.random() * 15 + 's';
    列20183.style.animationDuration = Math.random() * 14 + 8 + 's';
    列20183.style.fontSize = Math.random() * 4 + 12 + 'px';
    列20183.style.opacity = (Math.random() * 0.7 + 0.3).toFixed(2);
    let 文本20182 = '';
    const 字符数量 = Math.floor(Math.random() * 30 + 18);
    for (let 次索引值 = 0; 次索引值 < 字符数量; 次索引值++) {
      const 字符 = 赛博字符列表[Math.floor(Math.random() * 赛博字符列表.length)];
      const 值强调 = Math.random() > 0.85;
      const 颜色 = 值强调 ? 调色板[Math.floor(Math.random() * 调色板.length)] : '';
      文本20182 += 颜色 ? '<span style="color:' + 颜色 + ';' + 颜色 + ';">' + 字符 + '</span><br>' : '<span>' + 字符 + '</span><br>';
    }
    列20183.innerHTML = 文本20182;
    矩阵值.appendChild(列20183);
  }
  setInterval(function () {
    const 列列表 = 矩阵值.querySelectorAll('.matrix-column');
    列列表.forEach(function (列) {
      if (Math.random() > 0.94) {
        const 字符列表 = 列.querySelectorAll('span');
        if (字符列表.length > 0) {
          const 目标20181 = 字符列表[Math.floor(Math.random() * 字符列表.length)];
          const 本地值20180 = 目标20181.style.color;
          目标20181.style.color = 'var(--cp-on-accent)';
          目标20181
          setTimeout(function () {
            目标20181.style.color = 本地值20180;
            目标20181
          }, 200);
        }
      }
    });
  }, 110);
}
async function 检查系统状态() {
  try {
    const 云墙状态 = document.getElementById('cfStatus');
    const 地区状态 = document.getElementById('regionStatus');
    const 值值20179 = document.getElementById('geoInfo');
    const 备用状态 = document.getElementById('backupStatus');
    const 当前地址 = document.getElementById('currentIP');
    const 地区值 = document.getElementById('regionMatch');

    // 获取当前语言设置（优先从Cookie/localStorage读取）
    function 获取凭据20178(名称20177) {
      const 值20176 = '; ' + document.cookie;
      const 部分列表20175 = 值20176.split('; ' + 名称20177 + '=');
      if (部分列表20175.length === 2) return 部分列表20175.pop().split(';').shift();
      return null;
    }
    const 浏览器语言20174 = navigator.language || navigator.userLanguage || '';
    const 已保存语言20173 = localStorage.getItem('preferredLanguage') || 获取凭据20178('preferredLanguage');
    let 是否值20172 = false;
    if (已保存语言20173 === 'fa' || 已保存语言20173 === 'fa-IR') {
      是否值20172 = true;
    } else if (已保存语言20173 === 'zh' || 已保存语言20173 === 'zh-CN') {
      是否值20172 = false;
    } else {
      是否值20172 = 浏览器语言20174.includes('fa') || 浏览器语言20174.includes('fa-IR');
    }
    const 本地值20171 = {
      zh: {
        workerRegion: 'Worker地区: ',
        detectionMethod: '检测方式: ',
        proxyIPStatus: '${n("UHJveHlJUOeKtuaAgTog")}',
        currentIP: '当前使用IP: ',
        regionMatch: '地区匹配: ',
        regionNames: {
          'CF': '${n("8J+MkCDlrpjmlrnnm7Tov54=")}',
          'HK': '🇭🇰 香港',
          'US': '🇺🇸 美国',
          'SG': '🇸🇬 新加坡',
          'JP': '🇯🇵 日本',
          'KR': '🇰🇷 韩国',
          'DE': '🇩🇪 德国',
          'SE': '🇸🇪 瑞典',
          'NL': '🇳🇱 荷兰',
          'FI': '🇫🇮 芬兰',
          'GB': '🇬🇧 英国'
        },
        customIPMode: '${n("6Ieq5a6a5LmJUHJveHlJUOaooeW8jyAocOWPmOmHj+WQr+eUqCk=")}',
        customIPModeDesc: '自定义IP模式 (已禁用地区匹配)',
        usingCustomProxyIP: '${n("5L2/55So6Ieq5a6a5LmJUHJveHlJUDog")}',
        customIPConfig: ' (p变量配置)',
        customIPModeDisabled: '自定义IP模式，地区选择已禁用',
        manualRegion: '手动指定地区',
        manualRegionDesc: ' (手动指定)',
        proxyIPAvailable: '${n("MTAvMTAg5Y+v55SoIChQcm94eUlQ5Z+f5ZCN6aKE6K6+5Y+v55SoKQ==")}',
        smartSelection: '智能就近选择中',
        sameRegionIP: '同地区IP可用 (1个)',
        cloudflareDetection: '${n("5a6Y5pa555u06L+e")}',
        detectionFailed: '检测失败',
        unknown: '未知'
      },
      fa: {
        workerRegion: 'منطقه Worker: ',
        detectionMethod: 'روش تشخیص: ',
        proxyIPStatus: '${n("2YjYtti524zYqiBQcm94eUlQOiA=")}',
        currentIP: 'IP فعلی: ',
        regionMatch: 'تطبیق منطقه: ',
        regionNames: {
          'CF': '🌐 مستقیم رسمی',
          'HK': '🇭🇰 هنگ کنگ',
          'US': '🇺🇸 آمریکا',
          'SG': '🇸🇬 سنگاپور',
          'JP': '🇯🇵 ژاپن',
          'KR': '🇰🇷 کره جنوبی',
          'DE': '🇩🇪 آلمان',
          'SE': '🇸🇪 سوئد',
          'NL': '🇳🇱 هلند',
          'FI': '🇫🇮 فنلاند',
          'GB': '🇬🇧 بریتانیا'
        },
        customIPMode: '${n("2K3Yp9mE2KogUHJveHlJUCDYs9mB2KfYsdi024wgKNmF2KrYutuM2LEgcCDZgdi52KfZhCDYp9iz2Kop")}',
        customIPModeDesc: 'حالت IP سفارشی (تطبیق منطقه غیرفعال است)',
        usingCustomProxyIP: '${n("2KfYs9iq2YHYp9iv2Ycg2KfYsiBQcm94eUlQINiz2YHYp9ix2LTbjDog")}',
        customIPConfig: ' (پیکربندی متغیر p)',
        customIPModeDisabled: 'حالت IP سفارشی، انتخاب منطقه غیرفعال است',
        manualRegion: 'تعیین منطقه دستی',
        manualRegionDesc: ' (تعیین دستی)',
        proxyIPAvailable: '${n("MTAvMTAg2K/YsSDYr9iz2KrYsdizICjYr9in2YXZhtmHINm+24zYtOKAjNmB2LHYtiBQcm94eUlQINiv2LEg2K/Ys9iq2LHYsyDYp9iz2Kop")}',
        smartSelection: 'انتخاب هوشمند نزدیک در حال انجام است',
        sameRegionIP: 'IP هم‌منطقه در دسترس است (1)',
        cloudflareDetection: 'اتصال مستقیم رسمی',
        detectionFailed: 'تشخیص ناموفق',
        unknown: 'ناشناخته'
      }
    };
    const 翻译值20170 = 本地值20171[是否值20172 ? 'fa' : 'zh'];
    let 值地区20169 = 'US'; // 默认值
    let 是否自定义地址值 = false;
    let 是否手动地区值 = false;
    try {
      const 响应20168 = await fetch(window.CFNEW.apiBase + '/region');
      const 数据20167 = await 响应20168.json();
      if (数据20167.region === 'CUSTOM') {
        是否自定义地址值 = true;
        值地区20169 = 'CUSTOM';

        // 获取自定义IP的详细信息
        const 自定义地址值 = 数据20167.ci || 翻译值20170.unknown;
        值值20179.innerHTML = 翻译值20170.detectionMethod + '<span style="color: var(--cp-warning);">⚙️ ' + 翻译值20170.customIPMode + '</span>';
        地区状态.innerHTML = 翻译值20170.workerRegion + '<span style="color: var(--cp-warning);">🔧 ' + 翻译值20170.customIPModeDesc + '</span>';

        // 显示自定义IP配置状态，包含具体IP
        if (备用状态) 备用状态.innerHTML = 翻译值20170.proxyIPStatus + '<span style="color: var(--cp-warning);">🔧 ' + 翻译值20170.usingCustomProxyIP + 自定义地址值 + '</span>';
        if (当前地址) 当前地址.innerHTML = 翻译值20170.currentIP + '<span style="color: var(--cp-warning);">✅ ' + 自定义地址值 + 翻译值20170.customIPConfig + '</span>';
        if (地区值) 地区值.innerHTML = 翻译值20170.regionMatch + '<span style="color: var(--cp-warning);">⚠️ ' + 翻译值20170.customIPModeDisabled + '</span>';
        return; // 提前返回，不执行后续的地区匹配逻辑
      } else if (数据20167.detectionMethod === '手动指定地区' || 数据20167.detectionMethod === 'تعیین منطقه دستی') {
        是否手动地区值 = true;
        值地区20169 = 数据20167.region;
        值值20179.innerHTML = 翻译值20170.detectionMethod + '<span style="color: var(--cp-success);">' + 翻译值20170.manualRegion + '</span>';
        地区状态.innerHTML = 翻译值20170.workerRegion + '<span style="color: var(--cp-success);">🎯 ' + 翻译值20170.regionNames[值地区20169] + 翻译值20170.manualRegionDesc + '</span>';

        // 显示配置状态而不是检测状态
        if (备用状态) 备用状态.innerHTML = 翻译值20170.proxyIPStatus + '<span style="color: var(--cp-success);">✅ ' + 翻译值20170.proxyIPAvailable + '</span>';
        if (当前地址) 当前地址.innerHTML = 翻译值20170.currentIP + '<span style="color: var(--cp-success);">✅ ' + 翻译值20170.smartSelection + '</span>';
        if (地区值) 地区值.innerHTML = 翻译值20170.regionMatch + '<span style="color: var(--cp-success);">✅ ' + 翻译值20170.sameRegionIP + '</span>';
        return; // 提前返回，不执行后续的地区匹配逻辑
      } else if (数据20167.region && 翻译值20170.regionNames[数据20167.region]) {
        值地区20169 = 数据20167.region;
      }
      值值20179.innerHTML = 翻译值20170.detectionMethod + '<span style="color: var(--cp-success);">' + 翻译值20170.cloudflareDetection + '</span>';
    } catch (事件值20166) {
      值值20179.innerHTML = 翻译值20170.detectionMethod + '<span style="color: var(--cp-danger);">' + 翻译值20170.detectionFailed + '</span>';
    }
    地区状态.innerHTML = 翻译值20170.workerRegion + '<span style="color: var(--cp-success);">✅ ' + 翻译值20170.regionNames[值地区20169] + '</span>';

    // 直接显示配置状态，不再进行检测
    if (备用状态) {
      备用状态.innerHTML = 翻译值20170.proxyIPStatus + '<span style="color: var(--cp-success);">✅ ' + 翻译值20170.proxyIPAvailable + '</span>';
    }
    if (当前地址) {
      当前地址.innerHTML = 翻译值20170.currentIP + '<span style="color: var(--cp-success);">✅ ' + 翻译值20170.smartSelection + '</span>';
    }
    if (地区值) {
      地区值.innerHTML = 翻译值20170.regionMatch + '<span style="color: var(--cp-success);">✅ ' + 翻译值20170.sameRegionIP + '</span>';
    }
  } catch (错误20165) {
    function 获取凭据20164(名称20163) {
      const 值20162 = '; ' + document.cookie;
      const 部分列表20161 = 值20162.split('; ' + 名称20163 + '=');
      if (部分列表20161.length === 2) return 部分列表20161.pop().split(';').shift();
      return null;
    }
    const 浏览器语言20160 = navigator.language || navigator.userLanguage || '';
    const 已保存语言20159 = localStorage.getItem('preferredLanguage') || 获取凭据20164('preferredLanguage');
    let 是否值20158 = false;
    if (已保存语言20159 === 'fa' || 已保存语言20159 === 'fa-IR') {
      是否值20158 = true;
    } else {
      是否值20158 = 浏览器语言20160.includes('fa') || 浏览器语言20160.includes('fa-IR');
    }
    const 本地值20157 = {
      zh: {
        workerRegion: 'Worker地区: ',
        detectionMethod: '检测方式: ',
        proxyIPStatus: '${n("UHJveHlJUOeKtuaAgTog")}',
        currentIP: '当前使用IP: ',
        regionMatch: '地区匹配: ',
        detectionFailed: '检测失败'
      },
      fa: {
        workerRegion: 'منطقه Worker: ',
        detectionMethod: 'روش تشخیص: ',
        proxyIPStatus: '${n("2YjYtti524zYqiBQcm94eUlQOiA=")}',
        currentIP: 'IP فعلی: ',
        regionMatch: 'تطبیق منطقه: ',
        detectionFailed: 'تشخیص ناموفق'
      }
    };
    const 翻译值20156 = 本地值20157[是否值20158 ? 'fa' : 'zh'];
    document.getElementById('regionStatus').innerHTML = 翻译值20156.workerRegion + '<span style="color: var(--cp-danger);">❌ ' + 翻译值20156.detectionFailed + '</span>';
    document.getElementById('geoInfo').innerHTML = 翻译值20156.detectionMethod + '<span style="color: var(--cp-danger);">❌ ' + 翻译值20156.detectionFailed + '</span>';
    document.getElementById('backupStatus').innerHTML = 翻译值20156.proxyIPStatus + '<span style="color: var(--cp-danger);">❌ ' + 翻译值20156.detectionFailed + '</span>';
    document.getElementById('currentIP').innerHTML = 翻译值20156.currentIP + '<span style="color: var(--cp-danger);">❌ ' + 翻译值20156.detectionFailed + '</span>';
    document.getElementById('regionMatch').innerHTML = 翻译值20156.regionMatch + '<span style="color: var(--cp-danger);">❌ ' + 翻译值20156.detectionFailed + '</span>';
  }
}
async function 测试接口() {
  try {
    function 获取凭据20155(名称20154) {
      const 值20153 = '; ' + document.cookie;
      const 部分列表20152 = 值20153.split('; ' + 名称20154 + '=');
      if (部分列表20152.length === 2) return 部分列表20152.pop().split(';').shift();
      return null;
    }
    const 浏览器语言20151 = navigator.language || navigator.userLanguage || '';
    const 已保存语言20150 = localStorage.getItem('preferredLanguage') || 获取凭据20155('preferredLanguage');
    let 是否值20149 = false;
    if (已保存语言20150 === 'fa' || 已保存语言20150 === 'fa-IR') {
      是否值20149 = true;
    } else {
      是否值20149 = 浏览器语言20151.includes('fa') || 浏览器语言20151.includes('fa-IR');
    }
    const 本地值20148 = {
      zh: {
        apiTestResult: 'API检测结果: ',
        apiTestTime: '检测时间: ',
        apiTestFailed: 'API检测失败: ',
        unknownError: '未知错误',
        apiTestError: 'API测试失败: '
      },
      fa: {
        apiTestResult: 'نتیجه تشخیص API: ',
        apiTestTime: 'زمان تشخیص: ',
        apiTestFailed: 'تشخیص API ناموفق: ',
        unknownError: 'خطای ناشناخته',
        apiTestError: 'تست API ناموفق: '
      }
    };
    const 翻译值20147 = 本地值20148[是否值20149 ? 'fa' : 'zh'];
    const 响应20146 = await fetch(window.CFNEW.apiBase + '/test-api');
    const 数据20145 = await 响应20146.json();
    if (数据20145.detectedRegion) {
      显示提示(翻译值20147.apiTestResult + 数据20145.detectedRegion + '\\n' + 翻译值20147.apiTestTime + 数据20145.timestamp, 'info', {
        duration: 5000
      });
    } else {
      显示提示(翻译值20147.apiTestFailed + (数据20145.error || 翻译值20147.unknownError), 'error', {
        duration: 4500
      });
    }
  } catch (错误20144) {
    function 获取凭据20143(名称20142) {
      const 值20141 = '; ' + document.cookie;
      const 部分列表20140 = 值20141.split('; ' + 名称20142 + '=');
      if (部分列表20140.length === 2) return 部分列表20140.pop().split(';').shift();
      return null;
    }
    const 浏览器语言20139 = navigator.language || navigator.userLanguage || '';
    const 已保存语言20138 = localStorage.getItem('preferredLanguage') || 获取凭据20143('preferredLanguage');
    let 是否值20137 = false;
    if (已保存语言20138 === 'fa' || 已保存语言20138 === 'fa-IR') {
      是否值20137 = true;
    } else {
      是否值20137 = 浏览器语言20139.includes('fa') || 浏览器语言20139.includes('fa-IR');
    }
    const 本地值20136 = {
      zh: {
        apiTestError: 'API测试失败: '
      },
      fa: {
        apiTestError: 'تست API ناموفق: '
      }
    };
    const 翻译值20135 = 本地值20136[是否值20137 ? 'fa' : 'zh'];
    显示提示(翻译值20135.apiTestError + 错误20144.message, 'error', {
      duration: 4500
    });
  }
}

// 配置管理相关函数
async function 检查键值状态() {
  const 接口网址20134 = window.CFNEW.apiBase + '/api/config';
  try {
    const 响应20133 = await fetch(接口网址20134);
    function 获取凭据20132(名称20131) {
      const 值20130 = '; ' + document.cookie;
      const 部分列表20129 = 值20130.split('; ' + 名称20131 + '=');
      if (部分列表20129.length === 2) return 部分列表20129.pop().split(';').shift();
      return null;
    }
    const 浏览器语言20128 = navigator.language || navigator.userLanguage || '';
    const 已保存语言20127 = localStorage.getItem('preferredLanguage') || 获取凭据20132('preferredLanguage');
    let 是否值20126 = false;
    if (已保存语言20127 === 'fa' || 已保存语言20127 === 'fa-IR') {
      是否值20126 = true;
    } else {
      是否值20126 = 浏览器语言20128.includes('fa') || 浏览器语言20128.includes('fa-IR');
    }
    const 本地值20125 = {
      zh: {
        kvDisabled: '⚠️ KV存储未启用或未配置',
        kvNotConfigured: 'KV存储未配置，无法使用配置管理功能。\\n\\n请在Cloudflare Workers中:\\n1. 创建KV命名空间\\n2. 绑定环境变量 C\\n3. 重新部署代码',
        kvNotEnabled: 'KV存储未配置',
        kvEnabled: '✅ KV存储已启用，可以使用配置管理功能',
        kvCheckFailed: '⚠️ KV存储检测失败',
        kvCheckFailedFormat: 'KV存储检测失败: 响应格式错误',
        kvCheckFailedStatus: 'KV存储检测失败 - 状态码: ',
        kvCheckFailedError: 'KV存储检测失败 - 错误: '
      },
      fa: {
        kvDisabled: '⚠️ ذخیره‌سازی KV فعال نیست یا پیکربندی نشده است',
        kvNotConfigured: 'ذخیره‌سازی KV پیکربندی نشده است، نمی‌توانید از عملکرد مدیریت تنظیمات استفاده کنید.\\n\\nلطفا در Cloudflare Workers:\\n1. فضای نام KV ایجاد کنید\\n2. متغیر محیطی C را پیوند دهید\\n3. کد را دوباره مستقر کنید',
        kvNotEnabled: 'ذخیره‌سازی KV پیکربندی نشده است',
        kvEnabled: '✅ ذخیره‌سازی KV فعال است، می‌توانید از مدیریت تنظیمات استفاده کنید',
        kvCheckFailed: '⚠️ بررسی ذخیره‌سازی KV ناموفق',
        kvCheckFailedFormat: 'بررسی ذخیره‌سازی KV ناموفق: خطای فرمت پاسخ',
        kvCheckFailedStatus: 'بررسی ذخیره‌سازی KV ناموفق - کد وضعیت: ',
        kvCheckFailedError: 'بررسی ذخیره‌سازی KV ناموفق - خطا: '
      }
    };
    const 翻译值20124 = 本地值20125[是否值20126 ? 'fa' : 'zh'];
    if (响应20133.status === 503) {
      // KV未配置
      document.getElementById('kvStatus').innerHTML = '<span style="color: var(--cp-warning);">' + 翻译值20124.kvDisabled + '</span>';
      document.getElementById('configCard').style.display = 'block';
      document.getElementById('currentConfig').textContent = 翻译值20124.kvNotConfigured;
    } else if (响应20133.ok) {
      try {
        const 数据20123 = await 响应20133.json();

        // 检查响应是否包含KV配置信息
        if (数据20123 && 数据20123.kvEnabled === true) {
          document.getElementById('kvStatus').innerHTML = '<span style="color: var(--cp-success);">' + 翻译值20124.kvEnabled + '</span>';
          document.getElementById('configContent').style.display = 'block';
          document.getElementById('configCard').style.display = 'block';
          await 加载当前配置();
        } else {
          document.getElementById('kvStatus').innerHTML = '<span style="color: var(--cp-warning);">' + 翻译值20124.kvDisabled + '</span>';
          document.getElementById('configCard').style.display = 'block';
          document.getElementById('currentConfig').textContent = 翻译值20124.kvNotEnabled;
        }
      } catch (数据对象错误) {
        document.getElementById('kvStatus').innerHTML = '<span style="color: var(--cp-warning);">' + 翻译值20124.kvCheckFailed + '</span>';
        document.getElementById('configCard').style.display = 'block';
        document.getElementById('currentConfig').textContent = 翻译值20124.kvCheckFailedFormat;
      }
    } else {
      document.getElementById('kvStatus').innerHTML = '<span style="color: var(--cp-warning);">' + 翻译值20124.kvDisabled + '</span>';
      document.getElementById('configCard').style.display = 'block';
      document.getElementById('currentConfig').textContent = 翻译值20124.kvCheckFailedStatus + 响应20133.status;
    }
  } catch (错误20122) {
    function 获取凭据(名称) {
      const 值20121 = '; ' + document.cookie;
      const 部分列表20120 = 值20121.split('; ' + 名称 + '=');
      if (部分列表20120.length === 2) return 部分列表20120.pop().split(';').shift();
      return null;
    }
    const 浏览器语言 = navigator.language || navigator.userLanguage || '';
    const 已保存语言 = localStorage.getItem('preferredLanguage') || 获取凭据('preferredLanguage');
    let 是否值 = false;
    if (已保存语言 === 'fa' || 已保存语言 === 'fa-IR') {
      是否值 = true;
    } else {
      是否值 = 浏览器语言.includes('fa') || 浏览器语言.includes('fa-IR');
    }
    const 本地值20119 = {
      zh: {
        kvDisabled: '⚠️ KV存储未启用或未配置',
        kvCheckFailedError: 'KV存储检测失败 - 错误: '
      },
      fa: {
        kvDisabled: '⚠️ ذخیره‌سازی KV فعال نیست یا پیکربندی نشده است',
        kvCheckFailedError: 'بررسی ذخیره‌سازی KV ناموفق - خطا: '
      }
    };
    const 翻译值20118 = 本地值20119[是否值 ? 'fa' : 'zh'];
    document.getElementById('kvStatus').innerHTML = '<span style="color: var(--cp-warning);">' + 翻译值20118.kvDisabled + '</span>';
    document.getElementById('configCard').style.display = 'block';
    document.getElementById('currentConfig').textContent = 翻译值20118.kvCheckFailedError + 错误20122.message;
  }
}
function 读取字段值(标识) {
  const 元素 = document.getElementById(标识);
  return 元素 ? 元素.value : '';
}

function 写入字段值(标识, 值 = '') {
  const 元素 = document.getElementById(标识);
  if (元素) 元素.value = 值 || '';
}

function 是否开关启用(值, 默认启用 = false) {
  if (值 === undefined || 值 === null || 值 === '') return 默认启用;
  if (值 === true || 值 === false) return 值;
  const 文本 = String(值).trim().toLowerCase();
  if (文本 === 'yes' || 文本 === 'true' || 文本 === '1' || 文本 === 'on') return true;
  if (文本 === 'no' || 文本 === 'false' || 文本 === '0' || 文本 === 'off') return false;
  return 默认启用;
}

function 写入开关值(标识, 值, 默认启用 = false) {
  const 元素 = document.getElementById(标识);
  if (元素) 元素.checked = 是否开关启用(值, 默认启用);
}

function 读取开关值(标识, 默认启用 = false) {
  const 元素 = document.getElementById(标识);
  if (!元素) return 默认启用 ? 'yes' : 'no';
  return 元素.checked ? 'yes' : 'no';
}

function 同步协议界面状态() {
  const 明文开关 = document.getElementById('ev');
  const 木马开关 = document.getElementById('et');
  const 扩展开关 = document.getElementById('ex');
  if (明文开关 && 木马开关 && 扩展开关 && !明文开关.checked && !木马开关.checked && !扩展开关.checked) {
    明文开关.checked = true;
  }
}

function 同步联动界面状态() {
  同步协议界面状态();
  const 加密客户端问候复选框 = document.getElementById('ech');
  const 端口控制 = document.getElementById('portControl');
  if (加密客户端问候复选框 && 端口控制 && 加密客户端问候复选框.checked) {
    端口控制.value = 'yes';
  }
  更新路径类型状态(读取字段值('customPath'));
  更新工作器地区状态();
}

function 应用配置到界面(配置) {
  写入字段值('wkRegion', 配置.wk);
  写入开关值('freeCpu', 配置.freeCpu, false);
  写入开关值('ev', 配置.ev, true);
  写入开关值('et', 配置.et, false);
  写入开关值('ex', 配置.ex, false);
  写入开关值('ech', 配置.ech, false);
  写入字段值('tp', 配置.tp);
  写入字段值('customDNS', 配置.customDNS);
  写入字段值('customECHDomain', 配置.customECHDomain);
  写入字段值('alpn', 配置.alpn);
  写入字段值('scu', 配置.scu);
  写入开关值('ena', 配置.ena, false);
  写入开关值('jk', 配置.jk, false);
  const 家宽按钮 = document.getElementById('jkClientBtn');
  if (家宽按钮) 家宽按钮.style.display = 是否开关启用(配置.jk, false) ? '' : 'none';
  写入开关值('epd', 配置.epd, true);
  写入开关值('epi', 配置.epi, true);
  写入开关值('egi', 配置.egi, true);
  写入开关值('ipv4Enabled', 配置.ipv4, true);
  写入开关值('ipv6Enabled', 配置.ipv6, true);
  写入开关值('ispMobile', 配置.ispMobile, true);
  写入开关值('ispUnicom', 配置.ispUnicom, true);
  写入开关值('ispTelecom', 配置.ispTelecom, true);
  写入字段值('customPath', 配置.d);
  写入字段值('customIP', 配置.p);
  写入字段值('yx', (配置.yx || '').split(/[,\\r\\n]+/).map(值 => 值.trim()).filter(Boolean).join('\\n'));
  写入字段值('yxURL', 配置.yxURL);
  写入字段值('socksConfig', 配置.s);
  写入字段值('customHomepage', 配置.homepage);
  写入字段值('apiEnabled', 配置.ae);
  写入字段值('regionMatching', 配置.rm);
  写入字段值('downgradeControl', 配置.qj);
  写入字段值('portControl', 配置.dkby);
  写入字段值('preferredControl', 配置.yxby);
  同步联动界面状态();
}

function 收集界面配置() {
  const 配置 = {
    wk: 读取字段值('wkRegion'),
    freeCpu: 读取开关值('freeCpu', false),
    ev: 读取开关值('ev', true),
    et: 读取开关值('et', false),
    ex: 读取开关值('ex', false),
    ech: 读取开关值('ech', false),
    tp: 读取字段值('tp'),
    customDNS: 读取字段值('customDNS'),
    customECHDomain: 读取字段值('customECHDomain'),
    alpn: 读取字段值('alpn'),
    d: 读取字段值('customPath'),
    p: 读取字段值('customIP'),
    yx: 读取字段值('yx'),
    yxURL: 读取字段值('yxURL'),
    s: 读取字段值('socksConfig'),
    homepage: 读取字段值('customHomepage'),
    scu: 读取字段值('scu'),
    ena: 读取开关值('ena', false),
    jk: 读取开关值('jk', false),
    epd: 读取开关值('epd', true),
    epi: 读取开关值('epi', true),
    egi: 读取开关值('egi', true),
    ae: 读取字段值('apiEnabled'),
    rm: 读取字段值('regionMatching'),
    qj: 读取字段值('downgradeControl'),
    dkby: 读取字段值('portControl'),
    yxby: 读取字段值('preferredControl'),
    ipv4: 读取开关值('ipv4Enabled', true),
    ipv6: 读取开关值('ipv6Enabled', true),
    ispMobile: 读取开关值('ispMobile', true),
    ispUnicom: 读取开关值('ispUnicom', true),
    ispTelecom: 读取开关值('ispTelecom', true)
  };
  if (document.getElementById('freeCpu')?.disabled) delete 配置.freeCpu;
  if (配置.ev === 'no' && 配置.et === 'no' && 配置.ex === 'no') {
    配置.ev = 'yes';
    写入开关值('ev', 'yes', true);
  }
  if (配置.ech === 'yes') {
    配置.dkby = 'yes';
    写入字段值('portControl', 'yes');
  }
  return 配置;
}

async function 加载当前配置() {
  const 接口网址20117 = window.CFNEW.apiBase + '/api/config';
  try {
    const 响应20116 = await fetch(接口网址20117);
    if (响应20116.status === 503) {
      document.getElementById('currentConfig').textContent = 'KV存储未配置，无法加载配置';
      return;
    }
    if (!响应20116.ok) {
      const 错误文本20115 = await 响应20116.text();
      document.getElementById('currentConfig').textContent = '加载配置失败: ' + 错误文本20115;
      return;
    }
    const 配置 = await 响应20116.json();

    // 过滤掉入口鉴权与 KV 状态字段。
    const 显示配置 = {};
    for (const [键20114, 值20113] of Object.entries(配置)) {
      if (键20114 !== 'kvEnabled' && 键20114 !== 'uuid' && 键20114 !== 'coreVersion') {
        显示配置[键20114] = 值20113;
      }
    }
    let 配置文本 = '当前配置:\\n';
    if (Object.keys(显示配置).length === 0) {
      配置文本 += '(暂无配置)';
    } else {
      for (const [键, 值20112] of Object.entries(显示配置)) {
        配置文本 += 键 + ': ' + (值20112 || '(未设置)') + '\\n';
      }
    }
    document.getElementById('currentConfig').textContent = 配置文本;

    应用配置到界面(配置);
  } catch (错误20111) {
    document.getElementById('currentConfig').textContent = '加载配置失败: ' + 错误20111.message;
  }
}

// 更新路径类型显示
function 更新路径类型状态(customPath) {
  const element = document.getElementById('pathTypeStatus');
  if (!element) return;
  element.replaceChildren();
  const configPath = document.createElement('div');
  configPath.textContent = '配置路径：' + (customPath || '/' + window.CFNEW.uuid);
  const label = document.createElement('div');
  label.textContent = '订阅地址：';
  const link = document.createElement('a');
  const 订阅显示 = window.CFNEW.subDisplayUrl || window.CFNEW.subUrl;
  link.href = window.CFNEW.subDisplayHref || window.CFNEW.subUrl;
  link.textContent = 订阅显示;
  link.style.cssText = 'color:var(--cp-accent);overflow-wrap:anywhere';
  label.append(link);
  element.append(configPath, label);
}
function 更新工作器地区状态() {
  const 自定义地址输入20108 = document.getElementById('customIP');
  const 值地区 = document.getElementById('wkRegion');
  const 值地区值 = document.getElementById('wkRegionHint');
  if (自定义地址输入20108 && 值地区) {
    const 是否有自定义地址 = 自定义地址输入20108.value.trim() !== '';
    值地区.disabled = 是否有自定义地址;

    // 添加视觉反馈
    if (是否有自定义地址) {
      值地区.style.opacity = '0.5';
      值地区.style.cursor = 'not-allowed';
      值地区.style.backgroundColor = 'var(--cp-surface-2)';
      // 显示提示信息
      if (值地区值) {
        值地区值.style.display = 'block';
        值地区值.style.color = 'var(--cp-warning)';
      }
    } else {
      值地区.style.opacity = '1';
      值地区.style.cursor = 'pointer';
      值地区.style.backgroundColor = 'var(--cp-field)';
      // 隐藏提示信息
      if (值地区值) {
        值地区值.style.display = 'none';
      }
    }
  }
}
async function 保存配置(配置数据20107) {
  try {
    if (typeof 配置数据20107.yx === 'string') 配置数据20107 = { ...配置数据20107, yx: 配置数据20107.yx.split(/[,\\r\\n]+/).map(值 => 值.trim()).filter(Boolean).join(',') };
    const 响应 = await fetch(window.CFNEW.apiBase + '/api/config', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(配置数据20107)
    });
    let 结果;
    try { 结果 = await 响应.json(); } catch {
      throw new Error(响应.status === 413 ? '配置过大，请减少优选条目或改用列表 URL' : '服务器响应格式异常（HTTP ' + 响应.status + '），请稍后重试');
    }
    if (!响应.ok || !结果 || 结果.success !== true) throw new Error(结果?.message || 结果?.error || '保存失败（HTTP ' + 响应.status + '）');
    await 加载当前配置();
    更新工作器地区状态();
    setTimeout(function () { window.location.reload(); }, 1500);
  } catch (错误) {
    显示状态('保存失败: ' + 错误.message, 'error');
    throw 错误;
  }
}

function 显示状态(消息20100, 类型20099) {
  const 状态值 = document.getElementById('statusMessage');
  if (状态值) {
    状态值.textContent = 消息20100;
    状态值.style.display = 'block';
    状态值.style.color = 类型20099 === 'success' ? 'var(--cp-success)' : 'var(--cp-danger)';
    状态值.style.borderColor = 类型20099 === 'success' ? 'var(--cp-success)' : 'var(--cp-danger)';
    setTimeout(function () {
      状态值.style.display = 'none';
    }, 3000);
  }
  // 同步在底部操作条上方弹出霓虹反馈
  if (typeof window.显示操作状态 === 'function') {
    window.显示操作状态(消息20100, 类型20099 === 'success' ? 'ok' : 'err');
  }
}
async function 重置全部配置() {
  if (confirm('确定要重置所有配置吗？这将清空所有KV配置，恢复为环境变量设置。')) {
    try {
      const 响应20098 = await fetch(window.CFNEW.apiBase + '/api/config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ...(document.getElementById('freeCpu')?.disabled ? {} : { freeCpu: '' }),
          wk: '',
          d: '',
          p: '',
          yx: '',
          yxURL: '',
          s: '',
          ae: '',
          rm: '',
          qj: '',
          dkby: '',
          yxby: '',
          ev: '',
          et: '',
          ex: '',
          ech: '',
          tp: '',
          customDNS: '',
          customECHDomain: '',
          scu: '',
          epd: '',
          epi: '',
          egi: '',
          ipv4: '',
          ipv6: '',
          ispMobile: '',
          ispUnicom: '',
          ispTelecom: '',
          homepage: '',
          alpn: ''
        })
      });
      if (响应20098.status === 503) {
        显示状态('KV存储未配置，无法重置配置。', 'error');
        return;
      }
      if (!响应20098.ok) {
        const 错误文本 = await 响应20098.text();

        // 尝试解析 JSON 错误信息
        try {
          const 错误数据 = JSON.parse(错误文本);
          显示状态(错误数据.message || '重置失败', 'error');
        } catch (解析错误) {
          // 如果不是 JSON，直接显示文本
          显示状态('重置失败: ' + 错误文本, 'error');
        }
        return;
      }
      const 结果20097 = await 响应20098.json();
      显示状态(结果20097.message || '配置已重置', 结果20097.success ? 'success' : 'error');
      if (结果20097.success) {
        await 加载当前配置();
        // 更新wk地区选择状态
        更新工作器地区状态();
        // 刷新页面以更新系统状态
        setTimeout(function () {
          window.location.reload();
        }, 1500);
      }
    } catch (错误20096) {
      显示状态('重置失败: ' + 错误20096.message, 'error');
    }
  }
}
async function 检查加密问候状态() {
  const 加密客户端问候状态值 = document.getElementById('echStatus');
  if (!加密客户端问候状态值) return;
  try {
    const 当前网址 = window.location.href;
    const 订阅网址 = window.CFNEW.subUrl;
    加密客户端问候状态值.innerHTML = 'ECH状态: <span style="color: var(--cp-warning);">检测中...</span>';
    const 响应20095 = await fetch(订阅网址, {
      method: 'GET',
      headers: {
        'Accept': 'text/plain'
      }
    });
    const 加密客户端问候状态头部 = 响应20095.headers.get('X-ECH-Status');
    const 加密客户端问候配置长度 = 响应20095.headers.get('X-ECH-Config-Length');
    if (加密客户端问候状态头部 === 'ENABLED') {
      加密客户端问候状态值.innerHTML = 'ECH状态: <span style="color: var(--cp-success);">✅ 已启用' + (加密客户端问候配置长度 ? ' (配置长度: ' + 加密客户端问候配置长度 + ')' : '') + '</span>';
    } else {
      加密客户端问候状态值.innerHTML = 'ECH状态: <span style="color: var(--cp-warning);">⚠️ 未启用</span>';
    }
  } catch (错误20094) {
    加密客户端问候状态值.innerHTML = 'ECH状态: <span style="color: var(--cp-danger);">❌ 检测失败: ' + 错误20094.message + '</span>';
  }
}
document.addEventListener('DOMContentLoaded', function () {
  创建矩阵雨();
  检查系统状态();
  检查键值状态();
  检查加密问候状态();

  // ECH 开启时自动联动开启仅TLS
  const 加密客户端问候复选框 = document.getElementById('ech');
  const 端口控制 = document.getElementById('portControl');
  if (加密客户端问候复选框 && 端口控制) {
    加密客户端问候复选框.addEventListener('change', function () {
      if (this.checked) {
        // ECH 开启时，自动设置仅TLS为 yes
        端口控制.value = 'yes';
      }
      同步联动界面状态();
    });

    // 页面加载时，如果 ECH 已勾选，也自动设置仅TLS
    if (加密客户端问候复选框.checked) {
      端口控制.value = 'yes';
    }
  }

  // 监听customIP输入框变化，实时更新wk地区选择状态
  const 自定义地址输入 = document.getElementById('customIP');
  if (自定义地址输入) {
    自定义地址输入.addEventListener('input', function () {
      同步联动界面状态();
    });
  }


  const 自定义路径输入 = document.getElementById('customPath');
  if (自定义路径输入) {
    自定义路径输入.addEventListener('input', function () {
      同步联动界面状态();
    });
  }

  ['ev', 'et', 'ex'].forEach(function (协议标识) {
    const 协议开关 = document.getElementById(协议标识);
    if (协议开关) {
      协议开关.addEventListener('change', function () {
        同步联动界面状态();
      });
    }
  });

  // 阻止表单默认提交（保存按钮已统一到底部操作条）
  ['regionForm', 'otherConfigForm', 'advancedConfigForm'].forEach(function (本地值20093) {
    const 表单值 = document.getElementById(本地值20093);
    if (表单值) 表单值.addEventListener('submit', function (事件值20092) {
      事件值20092.preventDefault();
    });
  });

  // 在任意输入框按下回车，触发统一保存
  document.querySelectorAll('#configContent input[type="text"], #configContent input[type="number"]').forEach(function (本地值20091) {
    本地值20091.addEventListener('keydown', function (事件值20090) {
      if (事件值20090.key === 'Enter') {
        事件值20090.preventDefault();
        保存全部配置();
      }
    });
  });

  // 统一保存：一次性收齐所有字段
  function 收集全部配置() {
    return 收集界面配置();
  }
  async function 保存全部配置() {
    // 至少启用一个通道
    const 值值20085 = document.getElementById('ev'),
      值值20084 = document.getElementById('et'),
      值值20083 = document.getElementById('ex');
    if (值值20085 && 值值20084 && 值值20083 && !值值20085.checked && !值值20084.checked && !值值20083.checked) {
      显示操作状态('${n(a?"2K3Yr9in2YLZhCDbjNqpINm+2LHZiNiq2qnZhCDYsdinINmB2LnYp9mEINqp2YbbjNivIQ==":"6Iez5bCR6ZyA6KaB5ZCv55So5LiA5Liq5Y2P6K6u77yB")}', 'err');
      显示提示('${n(a?"2K3Yr9in2YLZhCDbjNqpINm+2LHZiNiq2qnZhCDYsdinINmB2LnYp9mEINqp2YbbjNivIQ==":"6Iez5bCR6ZyA6KaB5ZCv55So5LiA5Liq5Y2P6K6u77yB")}', 'warn');
      return;
    }
    const 本地值20082 = document.getElementById('cpBtnSaveAll');
    if (本地值20082) {
      本地值20082.classList.add('cp-action-btn-saving');
      本地值20082.disabled = true;
    }
    try {
      await 保存配置(收集全部配置());
    } finally {
      if (本地值20082) {
        本地值20082.classList.remove('cp-action-btn-saving');
        本地值20082.disabled = false;
      }
    }
  }
  window.保存全部配置 = 保存全部配置;
  function 显示操作状态(消息, 类型) {
    const 本地值20081 = document.getElementById('cpActionStatus');
    if (!本地值20081) return;
    本地值20081.textContent = 消息;
    本地值20081.classList.toggle('cp-err', 类型 === 'err');
    本地值20081.classList.add('cp-show');
    clearTimeout(显示操作状态._t);
    显示操作状态._t = setTimeout(function () {
      本地值20081.classList.remove('cp-show');
    }, 2400);
  }
  window.显示操作状态 = 显示操作状态;

  // 绑定底部统一操作条
  const 值操作值 = document.getElementById('cpActionBar');
  const 值值保存值 = document.getElementById('cpBtnSaveAll');
  if (值值保存值) 值值保存值.addEventListener('click', async function () {
    值值保存值.classList.add('cp-action-btn-saving');
    try {
      await 保存全部配置();
      if (值操作值) 值操作值.classList.remove('cp-dirty');
    } finally {
      值值保存值.classList.remove('cp-action-btn-saving');
    }
  });
  const 值值值20080 = document.getElementById('cpBtnRefresh');
  if (值值值20080) 值值值20080.addEventListener('click', async function () {
    值值值20080.classList.add('cp-action-btn-saving');
    try {
      await 加载当前配置();
      if (值操作值) 值操作值.classList.remove('cp-dirty');
      显示操作状态('${a?"تنظیمات تازه‌سازی شد":"配置已刷新"}');
    } finally {
      值值值20080.classList.remove('cp-action-btn-saving');
    }
  });
  const 值值重置 = document.getElementById('cpBtnReset');
  if (值值重置) 值值重置.addEventListener('click', 重置全部配置);

  // 修改字段时把 FAB 标记为 "未保存"
  function 标记已修改() {
    if (值操作值) 值操作值.classList.add('cp-dirty');
  }
  const 已修改范围 = document.getElementById('configContent') || document;
  ['input', 'change'].forEach(function (本地值20079) {
    已修改范围.addEventListener(本地值20079, function (事件值20078) {
      const 本地值20077 = 事件值20078.target;
      if (!本地值20077 || !本地值20077.tagName) return;
      const 本地值20076 = 本地值20077.tagName.toLowerCase();
      if (本地值20076 === 'input' || 本地值20076 === 'select' || 本地值20076 === 'textarea') {
        // 跳过延迟测试相关输入，避免误触
        if (本地值20077.id && /^(latencyTestInput|fetchURLInput|latencyTestPort|randomIPCount|testThreads|ipSourceSelect)$/.test(本地值20077.id)) return;
        标记已修改();
      }
    });
  });

  // Ctrl+S / Cmd+S 触发保存
  window.addEventListener('keydown', function (事件值20075) {
    if ((事件值20075.ctrlKey || 事件值20075.metaKey) && (事件值20075.key === 's' || 事件值20075.key === 'S')) {
      事件值20075.preventDefault();
      if (值值保存值 && !值值保存值.classList.contains('cp-action-btn-saving')) {
        值值保存值.click();
      }
    }
  });
  let 测试值控制器 = null;
  let 测试结果列表 = [];
  const 开始测试值 = document.getElementById('startLatencyTest');
  const 值测试值 = document.getElementById('stopLatencyTest');
  const 测试状态 = document.getElementById('latencyTestStatus');
  const 测试结果列表值 = document.getElementById('latencyTestResults');
  const 结果列表列表 = document.getElementById('latencyResultsList');
  const 覆盖已选值 = document.getElementById('overwriteSelectedToYx');
  const 追加已选值 = document.getElementById('appendSelectedToYx');
  const 选择值值 = document.getElementById('selectAllResults');
  const 值值值 = document.getElementById('deselectAllResults');
  const 地址源选择 = document.getElementById('ipSourceSelect');
  const 手动输入值 = document.getElementById('manualInputDiv');
  const 网址获取值 = document.getElementById('urlFetchDiv');
  const 延迟测试输入 = document.getElementById('latencyTestInput');
  const 获取网址输入 = document.getElementById('fetchURLInput');
  const 延迟测试端口 = document.getElementById('latencyTestPort');
  const 随机地址数量 = document.getElementById('randomIPCount');
  const 云墙随机值 = document.getElementById('cfRandomDiv');
  const 随机数量值 = document.getElementById('randomCountDiv');
  const 生成云墙地址值 = document.getElementById('generateCFIPBtn');
  const 获取地址值 = document.getElementById('fetchIPBtn');
  if (延迟测试输入) {
    const 已保存测试输入 = localStorage.getItem('latencyTestInput');
    if (已保存测试输入) 延迟测试输入.value = 已保存测试输入;
    延迟测试输入.addEventListener('input', function () {
      localStorage.setItem('latencyTestInput', this.value);
    });
  }
  if (获取网址输入) {
    const 已保存获取网址 = localStorage.getItem('fetchURLInput');
    if (已保存获取网址) 获取网址输入.value = 已保存获取网址;
    获取网址输入.addEventListener('input', function () {
      localStorage.setItem('fetchURLInput', this.value);
    });
  }
  if (延迟测试端口) {
    const 已保存端口 = localStorage.getItem('latencyTestPort');
    if (已保存端口) 延迟测试端口.value = 已保存端口;
    延迟测试端口.addEventListener('input', function () {
      localStorage.setItem('latencyTestPort', this.value);
    });
  }
  if (随机地址数量) {
    const 已保存数量 = localStorage.getItem('randomIPCount');
    if (已保存数量) 随机地址数量.value = 已保存数量;
    随机地址数量.addEventListener('input', function () {
      localStorage.setItem('randomIPCount', this.value);
    });
    // 初始化时，如果默认是隐藏的，则禁用输入框
    if (随机数量值 && 随机数量值.style.display === 'none') {
      随机地址数量.disabled = true;
    }
  }
  const 测试线程数输入 = document.getElementById('testThreads');
  if (测试线程数输入) {
    const 已保存线程数 = localStorage.getItem('testThreads');
    if (已保存线程数) 测试线程数输入.value = 已保存线程数;
    测试线程数输入.addEventListener('input', function () {
      localStorage.setItem('testThreads', this.value);
    });
  }
  if (地址源选择) {
    const 已保存源 = localStorage.getItem('ipSourceSelect');
    const 当前源 = 已保存源 || 地址源选择.value || 'manual';
    if (已保存源) {
      地址源选择.value = 已保存源;
    }
    手动输入值.style.display = 当前源 === 'manual' ? 'block' : 'none';
    网址获取值.style.display = 当前源 === 'urlFetch' ? 'block' : 'none';
    云墙随机值.style.display = 当前源 === 'cfRandom' ? 'block' : 'none';
    随机数量值.style.display = 当前源 === 'cfRandom' ? 'block' : 'none';
    // 当隐藏时禁用输入框，避免表单验证错误
    if (随机地址数量) {
      随机地址数量.disabled = 当前源 !== 'cfRandom';
    }
  }
  const 云墙网段列表 = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'];
  function 从网段生成随机地址(网段20074) {
    const [基础地址, 前缀长度] = 网段20074.split('/');
    const 前缀 = parseInt(前缀长度);
    const 主机值 = 32 - 前缀;
    const 地址部分列表 = 基础地址.split('.').map(参数值20073 => parseInt(参数值20073));
    const 地址值 = 地址部分列表[0] << 24 | 地址部分列表[1] << 16 | 地址部分列表[2] << 8 | 地址部分列表[3];
    const 随机偏移 = Math.floor(Math.random() * Math.pow(2, 主机值));
    const 掩码 = 0xFFFFFFFF << 主机值 >>> 0;
    const 随机地址 = ((地址值 & 掩码) >>> 0) + 随机偏移 >>> 0;
    return [随机地址 >>> 24 & 0xFF, 随机地址 >>> 16 & 0xFF, 随机地址 >>> 8 & 0xFF, 随机地址 & 0xFF].join('.');
  }
  function 生成云墙随机地址(数量20072, 端口20071) {
    const 地址列表20070 = [];
    for (let 索引值20069 = 0; 索引值20069 < 数量20072; 索引值20069++) {
      const 网段 = 云墙网段列表[Math.floor(Math.random() * 云墙网段列表.length)];
      const 地址20068 = 从网段生成随机地址(网段);
      地址列表20070.push(地址20068 + ':' + 端口20071);
    }
    return 地址列表20070;
  }
  if (地址源选择) {
    地址源选择.addEventListener('change', function () {
      const 值 = this.value;
      localStorage.setItem('ipSourceSelect', 值);
      手动输入值.style.display = 值 === 'manual' ? 'block' : 'none';
      网址获取值.style.display = 值 === 'urlFetch' ? 'block' : 'none';
      云墙随机值.style.display = 值 === 'cfRandom' ? 'block' : 'none';
      随机数量值.style.display = 值 === 'cfRandom' ? 'block' : 'none';
      // 当隐藏时禁用输入框，避免表单验证错误
      if (随机地址数量) {
        随机地址数量.disabled = 值 !== 'cfRandom';
      }
    });
  }
  if (生成云墙地址值) {
    生成云墙地址值.addEventListener('click', function () {
      const 数量 = parseInt(document.getElementById('randomIPCount').value) || 20;
      const 端口20067 = document.getElementById('latencyTestPort').value || '443';
      const 地址列表 = 生成云墙随机地址(数量, 端口20067);
      document.getElementById('latencyTestInput').value = 地址列表.join(',');
      手动输入值.style.display = 'block';
      显示状态('${a?"تولید شد":"已生成"} ' + 数量 + ' ${a?"IP تصادفی CF":"个CF随机IP"}', 'success');
    });
  }
  if (获取地址值) {
    获取地址值.addEventListener('click', async function () {
      const 网址输入 = document.getElementById('fetchURLInput');
      const 获取网址 = 网址输入.value.trim();
      if (!获取网址) {
        显示提示('${a?"لطفا URL را وارد کنید":"请输入URL"}', 'warn');
        return;
      }
      获取地址值.disabled = true;
      获取地址值.textContent = '${a?"در حال دریافت...":"获取中..."}';
      try {
        // 支持多个 URL（逗号分隔）以及返回内容中逗号分隔的多个 IP/节点
        const 网址列表 = Array.from(new Set(获取网址.split(',').map(网址值20066 => 网址值20066.trim()).filter(网址值20065 => 网址值20065)));
        const 值项目列表 = [];
        for (const 网址值 of 网址列表) {
          const 响应 = await 请求优选操作('list', { url: 网址值 });
          if (!响应.ok) {
            throw new Error('HTTP ' + 响应.status + ' @ ' + 网址值);
          }
          const 文本20064 = await 响应.text();

          // 先按行分割，再在每行内按逗号分割，兼容“多行 + 逗号分隔”两种格式
          const 值网址项目列表 = 文本20064.split(/\\r?\\n/).map(行值20063 => 行值20063.trim()).filter(行值20062 => 行值20062 && !行值20062.startsWith('#')).flatMap(行值 => 行值.split(',').map(参数值20061 => 参数值20061.trim()).filter(参数值 => 参数值));
          值项目列表.push(...值网址项目列表);
        }
        if (值项目列表.length > 0) {
          document.getElementById('latencyTestInput').value = 值项目列表.join(',');
          手动输入值.style.display = 'block';
          显示状态('${a?"دریافت شد":"已获取"} ' + 值项目列表.length + ' ${a?"IP":"个IP"}', 'success');
        } else {
          显示状态('${a?"داده‌ای یافت نشد":"未获取到数据"}', 'error');
        }
      } catch (错误20060) {
        显示状态('${a?"خطا در دریافت":"获取失败"}: ' + 错误20060.message, 'error');
      } finally {
        获取地址值.disabled = false;
        获取地址值.textContent = '⬇ ${a?"دریافت IP":"获取IP"}';
      }
    });
  }
  if (开始测试值) {
    开始测试值.addEventListener('click', async function () {
      const 输入值20059 = document.getElementById('latencyTestInput');
      const 端口值 = document.getElementById('latencyTestPort');
      const 线程数值 = document.getElementById('testThreads');
      const 输入值 = 输入值20059.value.trim();
      const 默认端口 = 端口值.value || '443';
      const 线程数 = parseInt(线程数值.value) || 5;
      if (!输入值) {
        显示状态('${a?"لطفا IP یا دامنه وارد کنید":"请输入IP或域名"}', 'error');
        return;
      }
      const 本地值20058 = 输入值.split(',').map(翻译值20057 => 翻译值20057.trim()).filter(翻译值20056 => 翻译值20056);
      if (本地值20058.length === 0) return;
      开始测试值.style.display = 'none';
      值测试值.style.display = 'inline-block';
      测试状态.style.display = 'block';
      测试结果列表值.style.display = 'block';
      结果列表列表.innerHTML = '';
      测试结果列表 = [];
      if (城市筛选值) {
        城市筛选值.style.display = 'none';
      }
      测试值控制器 = new AbortController();
      let 本地值20055 = 0;
      const 本地值20054 = 本地值20058.length;
      function 解析目标(目标20053) {
        let 主机20052 = 目标20053;
        let 端口20051 = 默认端口;
        let 节点名称20050 = '';
        if (目标20053.includes('#')) {
          const 部分列表20049 = 目标20053.split('#');
          节点名称20050 = 部分列表20049[1] || '';
          主机20052 = 部分列表20049[0];
        }
        if (主机20052.split(':').length === 2 && !主机20052.startsWith('[')) {
          const 值值20048 = 主机20052.lastIndexOf(':');
          const 值端口 = 主机20052.substring(值值20048 + 1);
          if (/^[0-9]+$/.test(值端口)) {
            端口20051 = 值端口;
            主机20052 = 主机20052.substring(0, 值值20048);
          }
        } else if (主机20052.includes(']:')) {
          const 部分列表20047 = 主机20052.split(']:');
          主机20052 = 部分列表20047[0] + ']';
          端口20051 = 部分列表20047[1];
        }
        return {
          host: 主机20052,
          port: 端口20051,
          nodeName: 节点名称20050
        };
      }
      function 渲染结果(结果20046, 索引20045, 值值20044 = true) {
        // 只展示在线优选成功的结果，失败/超时的不再显示
        if (!结果20046.success) {
          return null;
        }
        const 结果项目 = document.createElement('div');
        结果项目.style.cssText = 'display: flex; align-items: center; padding: 8px; border-bottom: 1px solid var(--cp-border); gap: 10px;';
        结果项目.dataset.index = 索引20045;
        结果项目.dataset.colo = 结果20046.colo || '';
        if (!值值20044) {
          结果项目.style.display = 'none';
        }
        const 复选框20043 = document.createElement('input');
        复选框20043.type = 'checkbox';
        复选框20043.checked = true;
        复选框20043.disabled = false;
        复选框20043.dataset.index = 索引20045;
        复选框20043.style.cssText = 'width: 18px; height: 18px; cursor: pointer;';
        const 本地值20042 = document.createElement('div');
        本地值20042.style.cssText = 'flex: 1; font-family: var(--cp-font-mono); font-size: 13px;';
        const 机房名称20041 = 结果20046.colo ? 获取机房名称(结果20046.colo) : '';
        const 机房显示 = 机房名称20041 ? ' <span style="color: var(--cp-accent);">[' + 机房名称20041 + ']</span>' : '';
        本地值20042.innerHTML = '<span style="color: var(--cp-accent);">' + 结果20046.host + ':' + 结果20046.port + '</span>' + 机房显示 + ' <span style="color: var(--cp-warning);">' + 结果20046.latency + 'ms</span>';
        结果项目.appendChild(复选框20043);
        结果项目.appendChild(本地值20042);
        结果列表列表.appendChild(结果项目);
        return 结果项目;
      }
      async function 测试单项(目标) {
        if (测试值控制器.signal.aborted) return null;
        const {
          host: 主机20040,
          port: 端口20039,
          nodeName: 节点名称
        } = 解析目标(目标);
        const 结果20038 = await 测试延迟(主机20040, 端口20039, 测试值控制器.signal);
        结果20038.host = 主机20040;
        结果20038.port = 端口20039;
        结果20038.customNodeName = 节点名称;
        结果20038.nodeName = 结果20038.success && 结果20038.colo ? 节点名称 || 'CF-' + 结果20038.colo : 节点名称 || 主机20040;
        return 结果20038;
      }
      for (let 索引值20037 = 0; 索引值20037 < 本地值20054; 索引值20037 += 线程数) {
        if (测试值控制器.signal.aborted) break;
        const 本地值20036 = 本地值20058.slice(索引值20037, Math.min(索引值20037 + 线程数, 本地值20054));
        测试状态.textContent = '${a?"در حال تست":"测试中"}: ' + (索引值20037 + 1) + '-' + Math.min(索引值20037 + 线程数, 本地值20054) + '/' + 本地值20054 + ' (${a?"رشته‌ها":"线程"}: ' + 线程数 + ')';
        const 结果列表 = await Promise.all(本地值20036.map(翻译值 => 测试单项(翻译值)));
        for (const 结果20035 of 结果列表) {
          if (结果20035) {
            const 索引20034 = 测试结果列表.length;
            测试结果列表.push(结果20035);
            渲染结果(结果20035, 索引20034);
            本地值20055++;
          }
        }
      }
      测试状态.textContent = '${a?"تست کامل شد":"测试完成"}: ' + 本地值20055 + '/' + 本地值20054;
      开始测试值.style.display = 'inline-block';
      值测试值.style.display = 'none';

      // 更新城市选择器
      更新城市筛选();
    });
  }
  if (值测试值) {
    值测试值.addEventListener('click', function () {
      if (测试值控制器) {
        测试值控制器.abort();
      }
      开始测试值.style.display = 'inline-block';
      值测试值.style.display = 'none';
      测试状态.textContent = '${a?"تست متوقف شد":"测试已停止"}';
    });
  }
  if (选择值值) {
    选择值值.addEventListener('click', function () {
      const 本地值20033 = 结果列表列表.querySelectorAll('input[type="checkbox"]:not(:disabled)');
      本地值20033.forEach(本地值20032 => 本地值20032.checked = true);
    });
  }
  if (值值值) {
    值值值.addEventListener('click', function () {
      const 本地值20031 = 结果列表列表.querySelectorAll('input[type="checkbox"]');
      本地值20031.forEach(本地值20030 => 本地值20030.checked = false);
    });
  }

  // 获取选中项的通用函数
  function 获取已选项目() {
    const 本地值20029 = 结果列表列表.querySelectorAll('input[type="checkbox"]:checked');
    if (本地值20029.length === 0) {
      显示状态('${a?"لطفا حداقل یک مورد انتخاب کنید":"请至少选择一项"}', 'error');
      return null;
    }
    const 已选项目列表20028 = [];
    本地值20029.forEach(本地值20027 => {
      const 索引20026 = parseInt(本地值20027.dataset.index);
      const 结果20025 = 测试结果列表[索引20026];
      if (结果20025 && 结果20025.success) {
        const 机房名称 = 结果20025.customNodeName || (结果20025.colo ? 获取机房名称(结果20025.colo) : 结果20025.nodeName);
        const 安全主机 = 结果20025.host.includes(':') && !结果20025.host.startsWith('[') ? '[' + 结果20025.host + ']' : 结果20025.host;
        const 项目字符串 = 安全主机 + ':' + 结果20025.port + '#' + 机房名称;
        已选项目列表20028.push(项目字符串);
      }
    });
    return 已选项目列表20028;
  }

  // 覆盖添加
  if (覆盖已选值) {
    覆盖已选值.addEventListener('click', async function () {
      const 已选项目列表20024 = 获取已选项目();
      if (!已选项目列表20024 || 已选项目列表20024.length === 0) return;
      const 值输入20023 = document.getElementById('yx');
      const 新值20022 = 已选项目列表20024.join('\\n');
      值输入20023.value = 新值20022;
      覆盖已选值.disabled = true;
      追加已选值.disabled = true;
      覆盖已选值.textContent = '${a?"در حال ذخیره...":"保存中..."}';
      try {
        const 配置数据20021 = {
          p: document.getElementById('customIP').value,
          yx: 新值20022,
          yxURL: document.getElementById('yxURL').value,
          s: document.getElementById('socksConfig').value
        };
        await 保存配置(配置数据20021);
        显示状态('${a?"موفقیت‌آمیز بود":"已覆盖"} ' + 已选项目列表20024.length + ' ${a?"مورد و ذخیره شد":"项并已保存"}', 'success');
      } catch (错误20020) {
        显示状态('${a?"خطا در ذخیره":"保存失败"}: ' + 错误20020.message, 'error');
      } finally {
        覆盖已选值.disabled = false;
        追加已选值.disabled = false;
        覆盖已选值.textContent = '覆盖添加';
      }
    });
  }

  // 追加添加
  if (追加已选值) {
    追加已选值.addEventListener('click', async function () {
      const 已选项目列表 = 获取已选项目();
      if (!已选项目列表 || 已选项目列表.length === 0) return;
      const 值输入 = document.getElementById('yx');
      const 当前值 = 值输入.value.trim();
      const 新项目列表 = 已选项目列表.join('\\n');
      const 新值 = 当前值 ? 当前值 + '\\n' + 新项目列表 : 新项目列表;
      值输入.value = 新值;
      覆盖已选值.disabled = true;
      追加已选值.disabled = true;
      追加已选值.textContent = '${a?"در حال ذخیره...":"保存中..."}';
      try {
        const 配置数据 = {
          p: document.getElementById('customIP').value,
          yx: 新值,
          yxURL: document.getElementById('yxURL').value,
          s: document.getElementById('socksConfig').value
        };
        await 保存配置(配置数据);
        显示状态('${a?"موفقیت‌آمیز بود":"已追加"} ' + 已选项目列表.length + ' ${a?"مورد و ذخیره شد":"项并已保存"}', 'success');
      } catch (错误20019) {
        显示状态('${a?"خطا در ذخیره":"保存失败"}: ' + 错误20019.message, 'error');
      } finally {
        覆盖已选值.disabled = false;
        追加已选值.disabled = false;
        追加已选值.textContent = '追加添加';
      }
    });
  }
  function 地址转十六进制(地址) {
    const 部分列表 = 地址.split('.');
    if (部分列表.length !== 4) return null;
    let 十六进制 = '';
    for (let 索引值 = 0; 索引值 < 4; 索引值++) {
      const 数字 = parseInt(部分列表[索引值]);
      if (isNaN(数字) || 数字 < 0 || 数字 > 255) return null;
      十六进制 += 数字.toString(16).padStart(2, '0');
    }
    return 十六进制;
  }
  const 机房映射 = {
    'SJC': '🇺🇸 圣何塞',
    'LAX': '🇺🇸 洛杉矶',
    'SEA': '🇺🇸 西雅图',
    'SFO': '🇺🇸 旧金山',
    'DFW': '🇺🇸 达拉斯',
    'ORD': '🇺🇸 芝加哥',
    'IAD': '🇺🇸 华盛顿',
    'ATL': '🇺🇸 亚特兰大',
    'MIA': '🇺🇸 迈阿密',
    'DEN': '🇺🇸 丹佛',
    'PHX': '🇺🇸 凤凰城',
    'BOS': '🇺🇸 波士顿',
    'EWR': '🇺🇸 纽瓦克',
    'JFK': '🇺🇸 纽约',
    'LAS': '🇺🇸 拉斯维加斯',
    'MSP': '🇺🇸 明尼阿波利斯',
    'DTW': '🇺🇸 底特律',
    'PHL': '🇺🇸 费城',
    'CLT': '🇺🇸 夏洛特',
    'SLC': '🇺🇸 盐湖城',
    'PDX': '🇺🇸 波特兰',
    'SAN': '🇺🇸 圣地亚哥',
    'TPA': '🇺🇸 坦帕',
    'IAH': '🇺🇸 休斯顿',
    'MCO': '🇺🇸 奥兰多',
    'AUS': '🇺🇸 奥斯汀',
    'BNA': '🇺🇸 纳什维尔',
    'RDU': '🇺🇸 罗利',
    'IND': '🇺🇸 印第安纳波利斯',
    'CMH': '🇺🇸 哥伦布',
    'MCI': '🇺🇸 堪萨斯城',
    'OMA': '🇺🇸 奥马哈',
    'ABQ': '🇺🇸 阿尔伯克基',
    'OKC': '🇺🇸 俄克拉荷马城',
    'MEM': '🇺🇸 孟菲斯',
    'JAX': '🇺🇸 杰克逊维尔',
    'RIC': '🇺🇸 里士满',
    'BUF': '🇺🇸 布法罗',
    'PIT': '🇺🇸 匹兹堡',
    'CLE': '🇺🇸 克利夫兰',
    'CVG': '🇺🇸 辛辛那提',
    'MKE': '🇺🇸 密尔沃基',
    'STL': '🇺🇸 圣路易斯',
    'SAT': '🇺🇸 圣安东尼奥',
    'HNL': '🇺🇸 檀香山',
    'ANC': '🇺🇸 安克雷奇',
    'SMF': '🇺🇸 萨克拉门托',
    'ONT': '🇺🇸 安大略',
    'OAK': '🇺🇸 奥克兰',
    'HKG': '🇭🇰 香港',
    'TPE': '🇹🇼 台北',
    'TSA': '🇹🇼 台北松山',
    'KHH': '🇹🇼 高雄',
    'NRT': '🇯🇵 东京成田',
    'HND': '🇯🇵 东京羽田',
    'KIX': '🇯🇵 大阪关西',
    'ITM': '🇯🇵 大阪伊丹',
    'NGO': '🇯🇵 名古屋',
    'FUK': '🇯🇵 福冈',
    'CTS': '🇯🇵 札幌',
    'OKA': '🇯🇵 冲绳',
    'ICN': '🇰🇷 首尔仁川',
    'GMP': '🇰🇷 首尔金浦',
    'PUS': '🇰🇷 釜山',
    'SIN': '🇸🇬 新加坡',
    'BKK': '🇹🇭 曼谷',
    'DMK': '🇹🇭 曼谷廊曼',
    'KUL': '🇲🇾 吉隆坡',
    'CGK': '🇮🇩 雅加达',
    'MNL': '🇵🇭 马尼拉',
    'CEB': '🇵🇭 宿务',
    'HAN': '🇻🇳 河内',
    'SGN': '🇻🇳 胡志明',
    'DAD': '🇻🇳 岘港',
    'RGN': '🇲🇲 仰光',
    'PNH': '🇰🇭 金边',
    'REP': '🇰🇭 暹粒',
    'VTE': '🇱🇦 万象',
    'BOM': '🇮🇳 孟买',
    'DEL': '🇮🇳 新德里',
    'MAA': '🇮🇳 金奈',
    'BLR': '🇮🇳 班加罗尔',
    'CCU': '🇮🇳 加尔各答',
    'HYD': '🇮🇳 海得拉巴',
    'AMD': '🇮🇳 艾哈迈达巴德',
    'COK': '🇮🇳 科钦',
    'PNQ': '🇮🇳 浦那',
    'GOI': '🇮🇳 果阿',
    'CMB': '🇱🇰 科伦坡',
    'DAC': '🇧🇩 达卡',
    'KTM': '🇳🇵 加德满都',
    'ISB': '🇵🇰 伊斯兰堡',
    'KHI': '🇵🇰 卡拉奇',
    'LHE': '🇵🇰 拉合尔',
    'LHR': '🇬🇧 伦敦希思罗',
    'LGW': '🇬🇧 伦敦盖特威克',
    'STN': '🇬🇧 伦敦斯坦斯特德',
    'LTN': '🇬🇧 伦敦卢顿',
    'MAN': '🇬🇧 曼彻斯特',
    'EDI': '🇬🇧 爱丁堡',
    'BHX': '🇬🇧 伯明翰',
    'CDG': '🇫🇷 巴黎戴高乐',
    'ORY': '🇫🇷 巴黎奥利',
    'MRS': '🇫🇷 马赛',
    'LYS': '🇫🇷 里昂',
    'NCE': '🇫🇷 尼斯',
    'FRA': '🇩🇪 法兰克福',
    'MUC': '🇩🇪 慕尼黑',
    'TXL': '🇩🇪 柏林',
    'BER': '🇩🇪 柏林勃兰登堡',
    'HAM': '🇩🇪 汉堡',
    'DUS': '🇩🇪 杜塞尔多夫',
    'CGN': '🇩🇪 科隆',
    'STR': '🇩🇪 斯图加特',
    'AMS': '🇳🇱 阿姆斯特丹',
    'BRU': '🇧🇪 布鲁塞尔',
    'LUX': '🇱🇺 卢森堡',
    'ZRH': '🇨🇭 苏黎世',
    'GVA': '🇨🇭 日内瓦',
    'BSL': '🇨🇭 巴塞尔',
    'VIE': '🇦🇹 维也纳',
    'PRG': '🇨🇿 布拉格',
    'BUD': '🇭🇺 布达佩斯',
    'WAW': '🇵🇱 华沙',
    'KRK': '🇵🇱 克拉科夫',
    'MXP': '🇮🇹 米兰马尔彭萨',
    'LIN': '🇮🇹 米兰利纳特',
    'FCO': '🇮🇹 罗马',
    'VCE': '🇮🇹 威尼斯',
    'NAP': '🇮🇹 那不勒斯',
    'FLR': '🇮🇹 佛罗伦萨',
    'BGY': '🇮🇹 贝加莫',
    'MAD': '🇪🇸 马德里',
    'BCN': '🇪🇸 巴塞罗那',
    'PMI': '🇪🇸 帕尔马',
    'AGP': '🇪🇸 马拉加',
    'VLC': '🇪🇸 瓦伦西亚',
    'SVQ': '🇪🇸 塞维利亚',
    'BIO': '🇪🇸 毕尔巴鄂',
    'LIS': '🇵🇹 里斯本',
    'OPO': '🇵🇹 波尔图',
    'FAO': '🇵🇹 法鲁',
    'DUB': '🇮🇪 都柏林',
    'CPH': '🇩🇰 哥本哈根',
    'ARN': '🇸🇪 斯德哥尔摩',
    'GOT': '🇸🇪 哥德堡',
    'OSL': '🇳🇴 奥斯陆',
    'BGO': '🇳🇴 卑尔根',
    'HEL': '🇫🇮 赫尔辛基',
    'RIX': '🇱🇻 里加',
    'TLL': '🇪🇪 塔林',
    'VNO': '🇱🇹 维尔纽斯',
    'ATH': '🇬🇷 雅典',
    'SKG': '🇬🇷 塞萨洛尼基',
    'SOF': '🇧🇬 索非亚',
    'OTP': '🇷🇴 布加勒斯特',
    'BEG': '🇷🇸 贝尔格莱德',
    'ZAG': '🇭🇷 萨格勒布',
    'LJU': '🇸🇮 卢布尔雅那',
    'KBP': '🇺🇦 基辅',
    'IEV': '🇺🇦 基辅茹良尼',
    'ODS': '🇺🇦 敖德萨',
    'SVO': '🇷🇺 莫斯科谢列梅捷沃',
    'DME': '🇷🇺 莫斯科多莫杰多沃',
    'VKO': '🇷🇺 莫斯科伏努科沃',
    'LED': '🇷🇺 圣彼得堡',
    'IST': '🇹🇷 伊斯坦布尔',
    'SAW': '🇹🇷 伊斯坦布尔萨比哈',
    'ESB': '🇹🇷 安卡拉',
    'AYT': '🇹🇷 安塔利亚',
    'ADB': '🇹🇷 伊兹密尔',
    'TLV': '🇮🇱 特拉维夫',
    'AMM': '🇯🇴 安曼',
    'BEY': '🇱🇧 贝鲁特',
    'BAH': '🇧🇭 巴林',
    'KWI': '🇰🇼 科威特',
    'DXB': '🇦🇪 迪拜',
    'AUH': '🇦🇪 阿布扎比',
    'SHJ': '🇦🇪 沙迦',
    'DOH': '🇶🇦 多哈',
    'MCT': '🇴🇲 马斯喀特',
    'RUH': '🇸🇦 利雅得',
    'JED': '🇸🇦 吉达',
    'DMM': '🇸🇦 达曼',
    'CAI': '🇪🇬 开罗',
    'HBE': '🇪🇬 亚历山大',
    'SSH': '🇪🇬 沙姆沙伊赫',
    'CMN': '🇲🇦 卡萨布兰卡',
    'RAK': '🇲🇦 马拉喀什',
    'TUN': '🇹🇳 突尼斯',
    'ALG': '🇩🇿 阿尔及尔',
    'LOS': '🇳🇬 拉各斯',
    'ABV': '🇳🇬 阿布贾',
    'ACC': '🇬🇭 阿克拉',
    'NBO': '🇰🇪 内罗毕',
    'MBA': '🇰🇪 蒙巴萨',
    'ADD': '🇪🇹 亚的斯亚贝巴',
    'DAR': '🇹🇿 达累斯萨拉姆',
    'JNB': '🇿🇦 约翰内斯堡',
    'CPT': '🇿🇦 开普敦',
    'DUR': '🇿🇦 德班',
    'HRE': '🇿🇼 哈拉雷',
    'LUN': '🇿🇲 卢萨卡',
    'MRU': '🇲🇺 毛里求斯',
    'SEZ': '🇸🇨 塞舌尔',
    'SYD': '🇦🇺 悉尼',
    'MEL': '🇦🇺 墨尔本',
    'BNE': '🇦🇺 布里斯班',
    'PER': '🇦🇺 珀斯',
    'ADL': '🇦🇺 阿德莱德',
    'CBR': '🇦🇺 堪培拉',
    'OOL': '🇦🇺 黄金海岸',
    'CNS': '🇦🇺 凯恩斯',
    'AKL': '🇳🇿 奥克兰',
    'WLG': '🇳🇿 惠灵顿',
    'CHC': '🇳🇿 基督城',
    'ZQN': '🇳🇿 皇后镇',
    'NAN': '🇫🇯 楠迪',
    'PPT': '🇵🇫 帕皮提',
    'GUM': '🇬🇺 关岛',
    'GRU': '🇧🇷 圣保罗瓜鲁柳斯',
    'CGH': '🇧🇷 圣保罗孔戈尼亚斯',
    'GIG': '🇧🇷 里约热内卢',
    'BSB': '🇧🇷 巴西利亚',
    'CNF': '🇧🇷 贝洛奥里藏特',
    'POA': '🇧🇷 阿雷格里港',
    'CWB': '🇧🇷 库里蒂巴',
    'FOR': '🇧🇷 福塔莱萨',
    'REC': '🇧🇷 累西腓',
    'SSA': '🇧🇷 萨尔瓦多',
    'EZE': '🇦🇷 布宜诺斯艾利斯',
    'AEP': '🇦🇷 布宜诺斯艾利斯城',
    'COR': '🇦🇷 科尔多瓦',
    'MDZ': '🇦🇷 门多萨',
    'SCL': '🇨🇱 圣地亚哥',
    'LIM': '🇵🇪 利马',
    'BOG': '🇨🇴 波哥大',
    'MDE': '🇨🇴 麦德林',
    'CLO': '🇨🇴 卡利',
    'UIO': '🇪🇨 基多',
    'GYE': '🇪🇨 瓜亚基尔',
    'CCS': '🇻🇪 加拉加斯',
    'MVD': '🇺🇾 蒙得维的亚',
    'ASU': '🇵🇾 亚松森',
    'PTY': '🇵🇦 巴拿马城',
    'SJO': '🇨🇷 圣何塞',
    'GUA': '🇬🇹 危地马拉城',
    'SAL': '🇸🇻 圣萨尔瓦多',
    'TGU': '🇭🇳 特古西加尔巴',
    'MGA': '🇳🇮 马那瓜',
    'BZE': '🇧🇿 伯利兹城',
    'MEX': '🇲🇽 墨西哥城',
    'GDL': '🇲🇽 瓜达拉哈拉',
    'MTY': '🇲🇽 蒙特雷',
    'CUN': '🇲🇽 坎昆',
    'TIJ': '🇲🇽 蒂华纳',
    'SJD': '🇲🇽 圣何塞德尔卡沃',
    'YYZ': '🇨🇦 多伦多',
    'YVR': '🇨🇦 温哥华',
    'YUL': '🇨🇦 蒙特利尔',
    'YYC': '🇨🇦 卡尔加里',
    'YEG': '🇨🇦 埃德蒙顿',
    'YOW': '🇨🇦 渥太华',
    'YWG': '🇨🇦 温尼伯',
    'YHZ': '🇨🇦 哈利法克斯',
    'HAV': '🇨🇺 哈瓦那',
    'SJU': '🇵🇷 圣胡安',
    'SDQ': '🇩🇴 圣多明各',
    'PAP': '🇭🇹 太子港',
    'KIN': '🇯🇲 金斯顿',
    'NAS': '🇧🇸 拿骚',
    'MBJ': '🇯🇲 蒙特哥贝'
  };
  function 获取机房名称(机房20018) {
    return 机房映射[机房20018] || 机房20018;
  }

  // 城市筛选相关函数
  const 城市筛选值 = document.getElementById('cityFilterContainer');
  const 城市值值 = document.getElementById('cityCheckboxesContainer');
  function 更新城市筛选() {
    if (!城市筛选值 || !城市值值) return;

    // 从测试结果中提取所有可用的城市
    const 城市映射 = new Map();
    测试结果列表.forEach((结果20017, 索引20016) => {
      if (结果20017.success && 结果20017.colo) {
        const 机房20015 = 结果20017.colo;
        if (!城市映射.has(机房20015)) {
          城市映射.set(机房20015, {
            colo: 机房20015,
            name: 获取机房名称(机房20015),
            count: 0
          });
        }
        城市映射.get(机房20015).count++;
      }
    });
    if (城市映射.size === 0) {
      城市筛选值.style.display = 'none';
      return;
    }
    城市筛选值.style.display = 'block';
    城市值值.innerHTML = '';

    // 按城市名称排序
    const 城市列表 = Array.from(城市映射.values()).sort((甲值20014, 乙值20013) => 甲值20014.name.localeCompare(乙值20013.name));
    城市列表.forEach(城市 => {
      const 标签 = document.createElement('label');
      标签.style.cssText = 'display: inline-flex; align-items: center; cursor: pointer; color: var(--cp-accent); font-size: 0.85rem; padding: 4px 8px; background: var(--cp-surface-2); border: 1px solid var(--cp-border); border-radius: 4px;';
      const 复选框20012 = document.createElement('input');
      复选框20012.type = 'checkbox';
      复选框20012.value = 城市.colo;
      复选框20012.checked = true;
      复选框20012.dataset.colo = 城市.colo;
      复选框20012.style.cssText = 'margin-right: 6px; width: 16px; height: 16px; cursor: pointer;';
      const 本地值20011 = document.createElement('span');
      本地值20011.textContent = 城市.name + ' (' + 城市.count + ')';
      标签.appendChild(复选框20012);
      标签.appendChild(本地值20011);
      城市值值.appendChild(标签);
      复选框20012.addEventListener('change', 按城市筛选结果);
    });

    // 监听筛选模式变化
    const 筛选值值 = document.querySelectorAll('input[name="cityFilterMode"]');
    筛选值值.forEach(单选框 => {
      单选框.addEventListener('change', function () {
        if (this.value === 'all') {
          // 切换到"全部城市"模式时，自动选中所有城市复选框
          const 城市值20010 = 城市值值.querySelectorAll('input[type="checkbox"]');
          城市值20010.forEach(本地值20009 => {
            本地值20009.checked = true;
            本地值20009.disabled = false;
          });
        }
        按城市筛选结果();
      });
    });
  }
  function 按城市筛选结果() {
    if (!结果列表列表 || !城市值值) return;
    const 筛选值 = document.querySelector('input[name="cityFilterMode"]:checked')?.value || 'all';
    const 结果项目列表 = 结果列表列表.querySelectorAll('[data-index]');
    const 城市值 = 城市值值.querySelectorAll('input[type="checkbox"]');
    if (筛选值 === 'fastest10') {
      // 只选择最快的10个
      const 值结果列表 = 测试结果列表.map((结果, 索引20008) => ({
        result: 结果,
        index: 索引20008
      })).filter(项目20007 => 项目20007.result.success).sort((甲值, 乙值) => 甲值.result.latency - 乙值.result.latency).slice(0, 10);
      const 最快索引集合 = new Set(值结果列表.map(项目20006 => 项目20006.index));
      结果项目列表.forEach(项目20005 => {
        const 索引 = parseInt(项目20005.dataset.index);
        const 复选框20004 = 项目20005.querySelector('input[type="checkbox"]');
        if (最快索引集合.has(索引)) {
          项目20005.style.display = 'flex';
          if (复选框20004) 复选框20004.checked = true;
        } else {
          项目20005.style.display = 'none';
          if (复选框20004) 复选框20004.checked = false;
        }
      });

      // 禁用城市复选框
      城市值.forEach(本地值20003 => 本地值20003.disabled = true);
    } else {
      // 根据选中的城市筛选
      const 已选城市列表 = new Set();
      城市值.forEach(本地值20002 => {
        if (本地值20002.checked) {
          已选城市列表.add(本地值20002.value);
        }
      });

      // 如果所有城市都被选中（或没有选中任何城市），显示所有结果
      const 值值20001 = 城市值.length > 0 && 已选城市列表.size === 城市值.length;
      const 值值 = 已选城市列表.size === 0;
      结果项目列表.forEach(项目 => {
        const 机房20000 = 项目.dataset.colo || '';
        const 复选框 = 项目.querySelector('input[type="checkbox"]');
        if (值值20001 || 值值 || 已选城市列表.has(机房20000)) {
          项目.style.display = 'flex';
          // 同步更新结果项复选框的选中状态
          if (复选框) {
            if (值值20001) {
              // 所有城市都选中时，所有结果项复选框都选中
              复选框.checked = true;
            } else if (值值) {
              // 没有选中任何城市时，所有结果项复选框都取消选中
              复选框.checked = false;
            } else {
              // 根据城市选择状态同步复选框
              复选框.checked = 已选城市列表.has(机房20000);
            }
          }
        } else {
          项目.style.display = 'none';
          // 取消选中隐藏的结果项复选框
          if (复选框) {
            复选框.checked = false;
          }
        }
      });

      // 启用城市复选框
      城市值.forEach(本地值 => 本地值.disabled = false);
    }
  }
  async function 测试延迟(主机, 端口, 信号) {
    try {
      const 响应 = await 请求优选操作('probe', { address: 主机.replace(/^\\[|\\]$/g, ''), port: Number(端口) }, 信号);
      const 结果 = await 响应.json();
      if (!响应.ok) throw new Error(结果.message || '检测失败');
      return 结果;
    } catch (错误) {
      return { success: false, latency: -1, error: 错误.message, colo: '' };
    }
  }

});
<\/script>
    </body>
    </html>`;return new Response(v,{status:200,headers:{"Content-Type":"text/html; charset=utf-8"}})}function Kt(t){return{头:t.slice(1,7),键:"_"+t.slice(25,31)}}async function Bt(){let t=U;try{let e=t.includes(",")?t.split(",").map(r=>r.trim()).filter(r=>r):[t],o=await Gt(e,"443",5e3);if(o.length>0){let r=[],v=/^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;for(let y of o){let x=y.match(v);x&&r.push({ip:be(x[1]),port:parseInt(x[2]||"443",10),name:x[3]?.trim()||x[1]})}return r}let s=await fetch(t);if(!s.ok)return[];let i=await s.text(),a=[],c=i.trim().replace(/\r/g,"").split(`
`),g=/^([^:]+):(\d+)#(.*)$/;for(let r of c){let v=r.trim();if(!v)continue;let y=v.match(g);y&&a.push({ip:y[1],port:parseInt(y[2],10),name:y[3].trim()||y[1]})}return a}catch{return[]}}function Ot(t,e,o,s=null,i=!1,a=null){let c=[80,8080,8880,2052,2082,2086,2095],g=[443,2053,2083,2087,2096,8443],r=[],v="/?ed=2048",y=atob("dmxlc3M="),x=a||oe(i);for(let d of t){let b=d.port,l=d.ip.includes(":")?`[${d.ip}]`:d.ip;if(g.includes(b)){let h=x(d),u=`${y}://${e}@${l}:${b}?encryption=none&security=tls&sni=${o}&fp=chrome&type=ws&host=${o}&path=${v}`;X&&(u+=`&alpn=${encodeURIComponent(X)}`),F&&(u+=`&ech=${encodeURIComponent(`${V||"cloudflare-ech.com"}+${j||"https://223.5.5.5/dns-query"}`)}`),u+=`#${encodeURIComponent(h)}`,r.push(u)}else if(c.includes(b)){if(!B){let h=x(d),u=`${y}://${e}@${l}:${b}?encryption=none&security=none&type=ws&host=${o}&path=${v}#${encodeURIComponent(h)}`;r.push(u)}}else{let h=x(d),u=`${y}://${e}@${l}:${b}?encryption=none&security=tls&sni=${o}&fp=chrome&type=ws&host=${o}&path=${v}`;X&&(u+=`&alpn=${encodeURIComponent(X)}`),F&&(u+=`&ech=${encodeURIComponent(`${V||"cloudflare-ech.com"}+${j||"https://223.5.5.5/dns-query"}`)}`),u+=`#${encodeURIComponent(h)}`,r.push(u)}}return r}function Xe(t,e,o,s=null,i=!1,a=null){let c=[],g=e.substring(0,8),r=a||oe(i);for(let v of t){let y=v.ip.includes(":")?`[${v.ip}]`:v.ip,x=v.port||443,d=r(v),b=new URLSearchParams({encryption:"none",security:"tls",sni:o,fp:"chrome",type:"xhttp",host:o,path:`/${g}`,mode:"stream-one"}),{头:l,键:h}=Kt(e);if(b.set("extra",JSON.stringify({xPaddingObfsMode:!0,xPaddingMethod:"tokenish",xPaddingPlacement:"queryInHeader",xPaddingHeader:l,xPaddingKey:h})),b.set("alpn","h2"),F){let u=j||"https://223.5.5.5/dns-query",w=V||"cloudflare-ech.com";b.set("ech",`${w}+${u}`)}c.push(`${n("dmxlc3M6Ly8=")}${e}@${y}:${x}?${b.toString()}#${encodeURIComponent(d)}`)}return c}async function zt(t,e,o,s=null,i=!1,a=null){let c=[80,8080,8880,2052,2082,2086,2095],g=[443,2053,2083,2087,2096,8443],r=[],v="/?ed=2048",y=W||e,x=a||oe(i);for(let d of t){let b=d.port,l=d.ip.includes(":")?`[${d.ip}]`:d.ip;if(g.includes(b)){let h=x(d),u=`${atob("dHJvamFuOi8v")}${y}@${l}:${b}?security=tls&sni=${o}&fp=chrome&type=ws&host=${o}&path=${v}`;X&&(u+=`&alpn=${encodeURIComponent(X)}`),F&&(u+=`&ech=${encodeURIComponent(`${V||"cloudflare-ech.com"}+${j||"https://223.5.5.5/dns-query"}`)}`),u+=`#${encodeURIComponent(h)}`,r.push(u)}else if(c.includes(b)){if(!B){let h=x(d),u=`${atob("dHJvamFuOi8v")}${y}@${l}:${b}?security=none&type=ws&host=${o}&path=${v}#${encodeURIComponent(h)}`;r.push(u)}}else{let h=x(d),u=`${atob("dHJvamFuOi8v")}${y}@${l}:${b}?security=tls&sni=${o}&fp=chrome&type=ws&host=${o}&path=${v}`;X&&(u+=`&alpn=${encodeURIComponent(X)}`),F&&(u+=`&ech=${encodeURIComponent(`${V||"cloudflare-ech.com"}+${j||"https://223.5.5.5/dns-query"}`)}`),u+=`#${encodeURIComponent(h)}`,r.push(u)}}return r}function Zt(){let t=mt(),e=t.wk;if(e&&e.trim())k=e.trim().toUpperCase(),C=k;else{let s=t.p;s&&s.trim()?C="CUSTOM":(k="",C="")}I=!(t.rm&&t.rm.toLowerCase()==="no"),A=t.ev==="yes",z=t.et==="yes",G=t.ex==="yes",W=t.tp||"",Ne=t.scu||ne.scu,fe=t.epd==="yes",ge=t.epi==="yes",Ye=t.egi==="yes",$e=t.ena==="yes",he=t.jk==="yes",F=t.ech==="yes",j=t.customDNS||ne.customDNS,V=t.customECHDomain||ne.customECHDomain,X=ze(t.alpn||""),B=t.dkby==="yes"||F;let o=(t.qj||"").toLowerCase();if(D=o==="no",T=o==="only",N=t.d||"",U=t.yxURL||"",S=t.p?t.p.trim():"",H=t.s||"",H)try{Be=Ft(H),ye=!0}catch{ye=!1}else Be={},ye=!1;q=!!(t.yxby&&t.yxby.toLowerCase()==="yes")}function qt(){let t=J("yx","");if(t)try{let e=t.split(/[,\r\n]+/).map(o=>o.trim()).filter(o=>o);R=[],K=[],e.forEach(o=>{let s="",i=o;if(o.includes("#")){let g=o.split("#");i=g[0].trim(),s=g[1].trim()}let{address:a,port:c}=xt(i);s||(s="自定义优选-"+a+(c?":"+c:"")),Oe(a)?R.push({ip:a,port:c,isp:s}):K.push({domain:a,port:c,name:s})})}catch{R=[],K=[]}else R=[],K=[]}async function Gt(t,e="443",o=3e3){if(!t?.length)return[];let s=new Set;return await Promise.allSettled(t.map(async i=>{try{let a=new AbortController,c=setTimeout(()=>a.abort(),o),g=await fetch(i,{signal:a.signal});clearTimeout(c);let r="";try{let d=await g.arrayBuffer(),l=(g.headers.get("content-type")||"").toLowerCase().match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase()||"",h=["utf-8","gb2312"];(l.includes("gb")||l.includes("gbk")||l.includes("gb2312"))&&(h=["gb2312","utf-8"]);let u=!1;for(let w of h)try{let $=new TextDecoder(w).decode(d);if($&&$.length>0&&!$.includes("�")){r=$,u=!0;break}else if($&&$.length>0)continue}catch{continue}if(u||(r=await g.text()),!r||r.trim().length===0)return}catch{return}let v=r.trim().split(`
`).map(d=>d.trim()).filter(d=>d),y=v.length>1&&v[0].includes(","),x=/^[^\[\]]*:[^\[\]]*:[^\[\]]/;if(!y)v.forEach(d=>{let b=d.indexOf("#"),[l,h]=b>-1?[d.substring(0,b),d.substring(b)]:[d,""],u=!1;if(l.startsWith("["))u=/\]:(\d+)$/.test(l);else{let $=l.lastIndexOf(":");u=$>-1&&/^\d+$/.test(l.substring($+1))}let w=new URL(i).searchParams.get("port")||e;s.add(u?d:`${l}:${w}${h}`)});else{let d=v[0].split(",").map(l=>l.trim()),b=v.slice(1);if(d.includes("IP地址")&&d.includes("端口")&&d.includes("数据中心")){let l=d.indexOf("IP地址"),h=d.indexOf("端口"),u=d.indexOf("国家")>-1?d.indexOf("国家"):d.indexOf("城市")>-1?d.indexOf("城市"):d.indexOf("数据中心"),w=d.indexOf("TLS");b.forEach($=>{let M=$.split(",").map(ee=>ee.trim());if(w!==-1&&M[w]?.toLowerCase()!=="true")return;let O=x.test(M[l])?`[${M[l]}]`:M[l];s.add(`${O}:${M[h]}#${M[u]}`)})}else if(d.some(l=>l.includes("IP"))&&d.some(l=>l.includes("延迟"))&&d.some(l=>l.includes("下载速度"))){let l=d.findIndex($=>$.includes("IP")),h=d.findIndex($=>$.includes("延迟")),u=d.findIndex($=>$.includes("下载速度")),w=new URL(i).searchParams.get("port")||e;b.forEach($=>{let M=$.split(",").map(ee=>ee.trim()),O=x.test(M[l])?`[${M[l]}]`:M[l];s.add(`${O}:${w}#CF优选 ${M[h]}ms ${M[u]}MB/s`)})}}}catch{}})),Array.from(s)}function Jt(t,e){return E=e,de=t,Zt(),C||="CF",qt(),{render:o=>jt(o,e),subscribe:o=>Mt(o,e),defaults:ne}}return Jt(p,m)}var st="2026.10.17.2";function it(p){let m=typeof p.coreVersion=="string"?p.coreVersion:"";return{panelVersion:st,coreVersion:m,needsUpdate:m!==st,changes:["新增 Free CPU 保护开关，按单连接双向流量和数据块预算提前断开。","默认关闭；开启后可能中断下载和视频，需客户端重连。更新配套内核后生效。"],zipUrl:"https://raw.githubusercontent.com/byJoey/cfnew/core-only/pages.zip",workerUrl:"https://raw.githubusercontent.com/byJoey/cfnew/core-only/_worker.js"}}var Se=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,at="https://cfnew-static.invalid";function nn(p){return JSON.stringify(p).replaceAll("<","\\u003c").replaceAll("\u2028","\\u2028").replaceAll("\u2029","\\u2029")}function on(p){let m=String(p||"").trim();if(!m)throw new Error("缺少 Worker 域名");let f=new URL(/^https?:\/\//i.test(m)?m:"https://"+m),n=["localhost","127.0.0.1","[::1]"].includes(f.hostname);if(f.username||f.password||f.search||f.hash)throw new Error("请输入 Worker 域名");if(f.pathname!=="/"&&f.pathname!=="")throw new Error("域名中不要带路径");if(!n&&(f.protocol!=="https:"||f.port&&f.port!=="443"))throw new Error("Worker 须使用 HTTPS");if(!["https:","http:"].includes(f.protocol))throw new Error("请输入 Worker 域名");return f.origin}function rn(p){let m=String(p||"").trim().replace(/^\/+|\/+$/g,"");if(!m||m.length>2048||/[?#\\\u0000-\u0020\u007f]/.test(m))throw new Error("请填写 UUID 或自定义路径");let f;try{f=decodeURIComponent(m)}catch{throw new Error("自定义路径格式无效")}if(/[?#\\\u0000-\u0020\u007f]/.test(f)||f.split("/").some(n=>n==="."||n===".."))throw new Error("自定义路径格式无效");return Se.test(m)?m.toLowerCase():new URL("/"+m,"https://path.invalid").pathname.slice(1)}function te(p){document.body.className="landing";let m=document.createElement("main"),f=document.createElement("div");f.className="header";let n=document.createElement("div");n.className="brand-mark brand-mark-lg",n.setAttribute("aria-hidden","true"),n.innerHTML='<svg viewBox="0 0 48 48" fill="none"><g stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M24 6.5v35"/><path d="M6.5 24h35"/><path d="M11.6 11.6l24.8 24.8"/><path d="M36.4 11.6L11.6 36.4"/></g></svg>';let E=document.createElement("h1");E.className="title",E.textContent="连接未完成",f.append(n,E);let S=document.createElement("div");S.className="card";let H=document.createElement("p");H.className="subtitle",H.style.textAlign="left",H.textContent=p;let R=document.createElement("a");R.href="index.html",R.textContent="返回重新填写",R.style.display="inline-block",R.style.marginTop="18px",S.append(H,R),m.append(f,S),document.body.replaceChildren(m)}function sn(){let p=window.__CFNEW_STATIC__,m=window.CFNEW,f="https://cfnew-static.invalid",n=window.fetch.bind(window);function E(I,C){try{window.显示提示(I,C||"info")}catch{}}function S(I){return/^sing-?box$/i.test(String(I||""))}let H=null;async function R(){if(!globalThis.__CFNEW_RULES_TEXT__){H||(H=n(new URL("assets/singbox-rules.json",location.href),{cache:"force-cache"}).then(I=>{if(!I.ok)throw new Error("HTTP "+I.status);return I.text()}).then(I=>{globalThis.__CFNEW_RULES_TEXT__=I}).catch(I=>{throw H=null,I}));try{await H}catch(I){throw new Error("分流规则加载失败："+(I&&I.message?I.message:I)+"，请刷新页面重试")}}}function K(I){return new Request(p.workerBase+"/"+p.uuid+"/sub?target="+encodeURIComponent(I||"base64"))}let D=document.querySelector(".container");if(D){let I=document.createElement("aside");I.className="static-notice";let C=document.createElement("strong");C.textContent="GitHub Pages 静态模式",I.append(C,document.createTextNode(" · 配置直接保存到你的 Worker；订阅在浏览器内生成并下载，无法提供自动更新的订阅链接。需要订阅链接请部署 Vercel 或 Docker 完整后端。下载的订阅文件包含 UUID，请勿公开分享。")),D.insertBefore(I,D.firstChild)}document.body.classList.add("static-mode");let T=m.release;if(T&&T.needsUpdate){let I=document.createElement("section");I.id="coreVersionStatus";let C=document.createElement("strong");C.textContent="内核需要更新";let k=document.createElement("div");k.textContent="面板版本 "+T.panelVersion+" · 内核版本 "+(T.coreVersion||"未标版本（旧内核）");let U=document.createElement("p");U.textContent="当前内核与面板版本不一致。请上传配套内核，保留原来的 u 和 C/c 绑定，然后刷新此页。";let N=document.createElement("details"),A=document.createElement("summary");A.textContent="本次更新了什么";let z=document.createElement("ul");for(let W of T.changes||[]){let F=document.createElement("li");F.textContent=W,z.append(F)}let G=document.createElement("div");G.className="release-downloads";for(let[W,F]of[["下载 pages.zip",T.zipUrl],["下载 _worker.js",T.workerUrl]]){let j=document.createElement("a");j.textContent=W,j.href=F,j.target="_blank",j.rel="noopener noreferrer",G.append(j)}N.append(A,z,G),I.append(C,k,U,N),document.body.prepend(I)}window.fetch=async function(I,C){let k=typeof I=="string"?I:I instanceof URL?I.href:I.url;if(k.startsWith(f+"/api/preferred/")){let U=k.slice(k.lastIndexOf("/")+1).split("?")[0],N={};try{N=JSON.parse(C&&C.body||"{}")}catch{}if(U==="probe")return Response.json({success:!1,latency:-1,colo:"",error:"静态模式无法在浏览器内检测 IP 可用性，请在客户端测速。"});if(U==="list"){if(!N.url)return new Response("",{status:400,headers:{"Content-Type":"text/plain; charset=utf-8"}});try{let A=await n(N.url,{headers:{Accept:"text/plain"}});if(!A.ok)throw new Error("HTTP "+A.status);return new Response(await A.text(),{headers:{"Content-Type":"text/plain; charset=utf-8"}})}catch(A){return E("列表来源需要允许跨域访问："+A.message,"warn"),new Response("",{status:502,headers:{"Content-Type":"text/plain; charset=utf-8"}})}}}if(k.startsWith(f+"/sub")){let U=new URL(k).searchParams.get("target")||"base64";try{return S(U)&&await R(),await p.engine.subscribe(K(U))}catch(N){return new Response("订阅生成失败："+N.message,{status:500,headers:{"Content-Type":"text/plain; charset=utf-8"}})}}return n(I,C)};function B(I){let C=String(I||"").toLowerCase();return C==="singbox"||C==="sing-box"?{ext:"json",mime:"application/json"}:C==="clash"||C==="stash"||C==="vg"?{ext:"yaml",mime:"text/yaml"}:{ext:"txt",mime:"text/plain"}}function q(I){return String(I||"").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"")||"subscription"}window.生成客户端链接=async function(I,C){let k=C||I,U=document.getElementById("clientSubscriptionUrl");try{S(I)&&await R();let N=await p.engine.subscribe(K(I)),A=await N.text();if(!N.ok)throw new Error(A||"HTTP "+N.status);let z=B(I),G=new Blob([A],{type:z.mime+";charset=utf-8"}),W=URL.createObjectURL(G),F=document.createElement("a");F.href=W,F.download="cfnew-"+q(k)+"."+z.ext,document.body.append(F),F.click(),F.remove(),setTimeout(()=>URL.revokeObjectURL(W),5e3),U&&(U.textContent="已下载 "+k+" 配置文件。静态模式不能提供自动更新的订阅链接。",U.style.display="block"),E(k+" 配置文件已生成","success")}catch(N){U&&(U.textContent="生成失败："+N.message,U.style.display="block"),E("生成失败："+N.message,"error")}}}async function an(){let p=new URLSearchParams(location.search),m,f;try{m=on(p.get("host")),f=rn(p.get("uuid"))}catch(k){te(k.message);return}let n;try{let k=typeof AbortSignal.timeout=="function"?AbortSignal.timeout(15e3):void 0;n=await fetch(m+"/"+f+"/api/config",{headers:{Accept:"application/json"},signal:k})}catch(k){te("读取 Worker 配置失败："+(k&&k.message?k.message:k)+"。静态模式要求内核允许跨域读取；请确认域名、UUID 或自定义路径正确。");return}if(!n.ok){let k="HTTP "+n.status;try{let U=await n.json();U&&U.message&&(k=U.message)}catch{}te("读取 Worker 配置失败："+k+"。请确认域名、UUID 或自定义路径和核心版本。");return}let E;try{E=await n.json()}catch{te("Worker 返回的配置不是有效 JSON。");return}if(!E||Array.isArray(E)||typeof E!="object"||typeof E.kvEnabled!="boolean"){te("该地址没有兼容的配置接口，请确认 Worker 内核版本。");return}let S=typeof E.uuid=="string"?E.uuid.toLowerCase():Se.test(f)?f:"";if(!Se.test(S)){te("请更新精简内核后再使用自定义路径登录。");return}let H=p.get("lang")||"";if(!H)try{H=localStorage.getItem("preferredLanguage")||""}catch{}H=["fa","fa-IR"].includes(H)?"fa":["zh","zh-CN"].includes(H)?"zh":"";let R={"Accept-Language":navigator.language||"zh-CN"};H&&(R.Cookie="preferredLanguage="+H);let K=rt({...E,uuid:S},S),D=await(await K.render(new Request(m+"/"+S,{headers:R}))).text(),T={host:m,uuid:S,apiBase:m+"/"+S,subPath:"",config:E,release:it(E),staticMode:!0,preferredApiBase:at,subUrl:at+"/sub?uuid="+S,subDisplayUrl:"静态模式：请在「选择客户端」中下载配置文件",subDisplayHref:"#"};window.__CFNEW_STATIC__={engine:K,workerBase:m,uuid:S};let B=new URL("assets/theme.css",location.href).href,q="<script>("+sn.toString()+")();<\/script>",I='<link rel="stylesheet" href="'+B+'"><script>window.CFNEW='+nn(T)+";<\/script>",C=D.replace("<head>",()=>"<head>"+I).replace("</body>",()=>q+"</body>");document.open(),document.write(C),document.close()}an().catch(p=>te("页面初始化失败："+(p&&p.message?p.message:p)));
