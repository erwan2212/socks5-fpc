program socks5;

uses windows,usocks5,
  rcmdline in '..\rcmdline-master\rcmdline.pas';

var
  tid: Cardinal;
  config : TSocks5config;
  cmd: TCommandLineReader;

begin
  cmd := TCommandLineReader.create;
  //cmd.declareString('ip', '192.168.1.254');
  cmd.declareInt('port', '1080',1080);
  cmd.declareString('username', '');
  cmd.declareString('password', '');

  cmd.parse(cmdline);

  if cmd.existsProperty('port')=false then
    begin
    writeln('https://github.com/erwan2212');
    writeln('Usage: socks5 --help');
    exit;
    end;

  config.Port     := cmd.readInt ('port');
  if cmd.readString('username')<>'' then config.UserName := pchar(cmd.readString('username'));
  if cmd.readString('password')<>'' then config.Password := pchar(cmd.readString('password'));

  {
  CreateThread(nil,0,@StartSocks5,@config,0,tid);
  while 1=1 do
        begin
          sleep(100);
        end;
  }

  StartSocks5(@config);

end.

