unit uSocks5;
{
+-----------------------------------------------------------+
|name:        uSocks5                                       |
|description: Establishes a SOCKS5 server, supporting AUTH   
|Author:      Hamtaro aka CorVu5                            |
|date:        16.10.09   / released: 24.10.09               |
|History:     first try                                     |
|ToDo:                                                      |
|       [*] Add support for Proxychains (!) & UDP (?)       |
|       [*] Add support for IPv6                            |
+-----------------------------------------------------------+
| This code can be changed or used without any restrictions |
+-----------------------------------------------------------+
}
interface
uses Windows, WinSock,sysutils;
type
  TSocks5Config = record
    Port     : Dword;
    UserName : String;
    Password : String;
end;
type PSocks5Config = ^TSocks5Config;
type
  TSocks5MethodSel = record
    Version  : Byte;
    nMethods : Byte;
    Methods : array[0..255] of Byte;
end;
type TSocks5Request = record
       ucVersion : byte;
       ucCommand : byte;
       ucRzv : byte;
       ucAtyp : byte;
       dwDestIp  : dword;
       wDestPort : word;
end;
function StartSocks5(conf : PSocks5Config) : Boolean; stdcall;
var
  config : TSocks5Config;
implementation

function GetIPAddr(aSocket: TSocket): string;
var
  addr: sockaddr_in;
  addrlen: integer;
  szIPAddr: PansiChar;
begin
  addrlen := sizeof(addr);
  getsockname(aSocket,addr,addrlen);
  szIPAddr := inet_ntoa(addr.sin_addr);
  Result := StrPas(szIPAddr);
end;

function GetPeerPort(aSocket: TSocket): string;
var
  addr: sockaddr_in;
  addrlen: integer;
begin
  addrlen := sizeof(addr);
  getpeername(aSocket,addr,addrlen);
  Result := IntToStr(ntohs(addr.sin_port));
end;

function GetPeerIPAddr(aSocket: TSocket): string;
var
  addr: sockaddr_in;
  addrlen: integer;
  szIPAddr: PansiChar;
begin
  addrlen := sizeof(addr);
  getpeername(aSocket,addr,addrlen);
  szIPAddr := inet_ntoa(addr.sin_addr);
  Result := StrPas(szIPAddr);
end;

function GetPort(aSocket: TSocket): string;
var
  addr: sockaddr_in;
  addrlen: integer;
begin
  addrlen := sizeof(addr);
  getsockname(aSocket,addr,addrlen);
  Result := IntToStr(ntohs(addr.sin_port));
end;


procedure SocksProc(sock : Cardinal); stdcall;
var
    m : TSocks5MethodSel;
    req : TSocks5Request;
    auth :array[0..1024-1] of Byte;
    buf  :array[0..512-1] of Byte;
    buffer : array[0..(1024*16)-1] of Byte;
    recv_len : Integer;
    i : Integer;
    recvsock : TSocket;
    UserName, password : String;
    tunneladdr_in : sockaddr_in;
    tunneldomain : String;
    tunnelsock : TSocket;
    hostent : PHostEnt;
    tv : Ttimeval;
    fset : tfdset;
    self_addr : sockaddr_in;
    self_Len : Integer;
begin
  writeln('SocksProc');
  recvsock := sock;
  if recv(recvsock,m,2,MSG_PEEK) > 0 then begin
    if m.Version = 5 then begin     //it is socks5
      recv(recvsock,m, 2 + m.nMethods,0); //request complete Header
      for i := 0 to m.nMethods - 1 Do begin
        if (m.Methods[i] = 2) then begin           //password auth
          if (config.UserName = '') and (config.Password = '') then begin
            m.nMethods := $00;
            send(recvsock, m,2,0);
            end else begin
            m.nMethods := 2;
            send(recvsock, m,2,0);
            recv(recvsock, auth,SizeOf(auth),0);
            if auth[0] = 1 Then begin
              //get username
              SetString(username,Pchar(@auth[2]),auth[1]);
              //get password
              SetString(password,Pchar(Cardinal(@auth) + 3 + auth[1]),auth[2 + auth[1]]);
              if (config.UserName = UserName) and (config.Password = password) then begin   //auth successful!
                auth[1] := 0;
                send(recvsock,auth,2,0);
              end else begin
                MessageBox(0,'auth fail','fffuuuuuuu-',0);
                auth[1] := $FF; //nothing but fail
                send(recvsock,auth,2,0);
                break;
              end;
            end;
          end;
        end else if (m.Methods[i] = 0) Then
        begin
          if (config.password = '') and (config.UserName = '') Then
          begin
            m.nMethods := 0;
            send(recvsock,m,2,0);
          end else
          begin
            m.nMethods := $FF;
            send(recvsock,m,2,0);
            break;
          end;
        end else if i = m.nMethods then
        begin
          m.nMethods := $FF;
          send(recvsock,m,2,0);
          Break;
        end;
        recv(recvsock, req, sizeof(Tsocks5Request), MSG_PEEK);
        if  req.ucCommand = 1 then
        begin        //TCP Verbindung, ok
          Zeromemory(@tunneladdr_in,sizeof(tunneladdr_in));
          if req.ucAtyp = 1 Then
          begin  //ip4
            recv(recvsock, req, sizeof(Tsocks5Request), 0);
            tunneladdr_in.sin_port := req.wDestPort;
            CopyMemory(@tunneladdr_in.sin_addr,@req.dwDestIp,sizeof(tunneladdr_in.sin_addr));
            //writeln('dwDestIp:'+strpas(inet_ntoa(tunneladdr_in.sin_addr)));
          end
          else
          if req.ucAtyp = 3 Then
          begin //domain name
            ZeroMemory(@buf,SizeOf(buf));
            recv(recvsock,buf,7 + Byte(req.dwDestIp),0);
            SetString(tunneldomain,PChar(Cardinal(@buf) + 5),Integer(Byte(req.dwDestIp)));
            //writeln('tunneldomain:'+tunneldomain);
            hostent := gethostbyname(PChar(tunneldomain));
            PInteger(@tunneladdr_in.sin_addr.S_addr)^:=PInteger(HostEnt^.h_addr^)^;
            tunneladdr_in.sin_port := htons(Word(Pointer(Cardinal(@buf) + 6 + Byte(req.dwDestIp))^));
          end; //todo: PIv6
          tunneladdr_in.sin_family := AF_INET;
          tunnelsock := socket(PF_INET, SOCK_STREAM, 0);
          if connect(tunnelsock,tunneladdr_in,sizeof(tunneladdr_in)) = 0 Then
          begin//success!
            req.ucCommand := 0;  //success
          end
          else
          begin
            req.ucCommand := 1; //General Failure reporting in
          end;
          req.ucVersion := 5;
          req.ucRzv := 0;
          req.ucAtyp := 1;
          ZeroMemory(@self_addr,SizeOf(sockaddr_in));
          self_Len := SizeOf(sockaddr_in);
          getsockname(tunnelsock,self_addr,self_len);
          CopyMemory(@req.dwDestIp,@self_addr.sin_addr,sizeof(self_addr.sin_addr));
          req.wDestPort := self_addr.sin_port;
          send(recvsock,req,10,0);
          //now tunneling everything!
          tv.tv_sec := 5;
          //between socks5 and remote ip
          writeln('tunnelsock peer:'+GetPeerIPAddr (tunnelsock )+':'+GetPeerPort(tunnelsock)  );
          //writeln('tunnelsock ip:'+GetipAddr (tunnelsock )+':'+GetPort (tunnelsock));
          {
          //between client app and proxy
          writeln('-');
          writeln('recvsock peer:'+GetPeerIPAddr (recvsock )+':'+GetPeerPort(recvsock)  );
          writeln('recvsock ip:'+GetipAddr (recvsock )+':'+GetPort (recvsock));
          }
          while 1 =1 Do
          begin
            //waiting for incoming data
            FD_ZERO(fset);
            FD_SET(recvsock,fset);
            FD_SET(tunnelsock,fset);
            if select(0,@fset,nil,nil,nil) <> SOCKET_ERROR Then
            begin
              if FD_ISSET(tunnelsock,fset) THEN
              begin //data on the tunnelsock
                ZeroMemory(@buffer,sizeof(buffer));
                recv_len := recv(tunnelsock, buffer,sizeof(buffer),0);
                if recv_len = SOCKET_ERROR Then break; //error?
                send(recvsock,buffer,recv_len,0);
              end; //if FD_ISSET(tunnelsock,fset) THEN
              if FD_ISSET(recvsock,fset) THEN
              begin //data on the recvsock
                ZeroMemory(@buffer,sizeof(buffer));
                recv_len := recv(recvsock, buffer,sizeof(buffer),0);
                if recv_len = SOCKET_ERROR Then break; //error?
                send(tunnelsock,buffer,recv_len,0);
              end; //if FD_ISSET(recvsock,fset) THEN
            end; //if select(0,@fset,nil,nil,nil) <> SOCKET_ERROR Then
            Sleep(50); //zzZZzzZZZZzz
          end; //while 1 =1 Do
        end;
        Break;
      end;
    end;
  end;
//  MessageBox(0,PChar('Error Code: ' + inttostr(WSAGetLastError)),'Error!',0);
  closesocket(recvsock);
  closesocket(tunnelsock);
end;
function StartSocks5(conf : PSocks5Config) : Boolean; stdcall;
var
  wsaData : TWSAData;
  sock    : TSOCKET;
  sockaddr: SockAddr_in;
  conn    : Integer;
  client  : TSockAddr;
  tid : Cardinal;
  size : Integer;
begin
  writeln('StartSocks5');
  result := False;
  Move(conf^,config,SizeOf(TSocks5Config));
  WSAStartup($101, wsaData);
  sock := socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  ZeroMemory(@SockAddr, sizeof(SockAddr));
  sockaddr.sin_family := AF_INET;
  sockaddr.sin_port   := htons(config.Port);
  sockaddr.sin_addr.S_addr   := INADDR_ANY;
  if (bind  (sock  ,sockaddr,SizeOf(sockaddr)) = 0) AND
     (listen(sock,SOMAXCONN)                   = 0) then begin
      while 1 = 1 Do begin
        size := SizeOf(client);
        conn := accept(sock,@client,@size);
        if conn <> SOCKET_ERROR then  begin
          CreateThread(nil,0,@SocksProc,Pointer(conn),0,tid);
        end;
        Sleep(100);
      end;
  end;
end;
end.
