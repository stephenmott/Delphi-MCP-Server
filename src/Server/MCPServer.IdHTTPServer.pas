unit MCPServer.IdHTTPServer;

interface

// TaurusTLS provides OpenSSL 3.x support with modern ECDHE cipher suites
// Install via GetIt Package Manager: Search for "TaurusTLS" or get from https://github.com/JPeterMugaas/TaurusTLS
{.$DEFINE USE_TAURUS_TLS}  // Comment this line to use standard Indy SSL (OpenSSL 1.0.2)

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Rtti,
  System.IOUtils,
  System.SyncObjs,
  System.Generics.Collections,
  IdHTTPServer,
  IdContext,
  IdCustomHTTPServer,
  IdGlobal,
  IdGlobalProtocols,
  {$IFDEF USE_TAURUS_TLS}
  TaurusTLS,
  {$ELSE}
  IdSSLOpenSSL,
  {$ENDIF}
  IdServerIOHandler,
  MCPServer.Types,
  MCPServer.Settings,
  MCPServer.JsonRpcProcessor;

type
  TAuthCodeEntry = record
    CodeChallenge: string;
    RedirectURI: string;
    State: string;
    ExpiresAt: TDateTime;
  end;

  TMCPIdHTTPServer = class(TComponent)
  private
    FHTTPServer: TIdHTTPServer;
    {$IFDEF USE_TAURUS_TLS}
    FSSLHandler: TTaurusTLSServerIOHandler;
    {$ELSE}
    FSSLHandler: TIdServerIOHandlerSSLOpenSSL;
    {$ENDIF}
    FManagerRegistry: IMCPManagerRegistry;
    FCoreManager: IMCPCapabilityManager;
    FJsonRpcProcessor: TMCPJsonRpcProcessor;
    FPort: Word;
    FActive: Boolean;
    FSettings: TMCPSettings;
    FEventIDCounter: Int64;
    FAuthCodes: TDictionary<string, TAuthCodeEntry>;
    FAuthCodesLock: TCriticalSection;
    procedure ConfigureSSL;
    procedure HandleQuerySSLPort(APort: Word; var VUseSSL: Boolean);
    procedure HandleHTTPRequest(Context: TIdContext; RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    function VerifyAndSetCORSHeaders(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo): Boolean;
    procedure HandleOptionsRequest(ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleGetRequest(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandlePostRequest(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandlePostRequestSSE(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo; const RequestBody: string; const SessionID: string);
    procedure HandlePostRequestJSON(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo; const RequestBody: string; const SessionID: string);
    function GetNextEventID: string;
    function AcceptsSSE(const AcceptHeader: string): Boolean;
    function IsRequestOnlyNotificationsOrResponses(JSONRequest: TJSONValue): Boolean;
    // OAuth helpers
    function Base64URLEncode(const Bytes: TBytes): string;
    function Base64URLDecode(const S: string): TBytes;
    function ParseFormParams(const Body: string): TDictionary<string, string>;
    function GetRequestBaseURL(RequestInfo: TIdHTTPRequestInfo): string;
    function GenerateAuthCode: string;
    procedure CleanExpiredAuthCodes;
    function GenerateJWT: string;
    function ValidateBearerToken(const Token: string): Boolean;
    function HTMLEncode(const S: string): string;
    function GetParam(Params: TDictionary<string, string>; const Key: string): string;
    // OAuth endpoint handlers
    procedure HandleWellKnownOAuth(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleProtectedResourceMetadata(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleRegister(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleAuthorize(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleToken(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
  public
    constructor Create(Owner: TComponent); override;
    destructor Destroy; override;
    procedure Start;
    procedure Stop;
    property Port: Word read FPort write FPort;
    property Active: Boolean read FActive;
    property ManagerRegistry: IMCPManagerRegistry read FManagerRegistry write FManagerRegistry;
    property CoreManager: IMCPCapabilityManager read FCoreManager write FCoreManager;
    property Settings: TMCPSettings read FSettings write FSettings;
  end;

implementation

uses
  MCPServer.Resource.Server,
  MCPServer.CoreManager,
  MCPServer.Logger,
  System.Hash,
  System.DateUtils,
  System.NetEncoding,
  IdURI;

const
  KEEP_ALIVE_TIMEOUT = 300;
  DEFAULT_MCP_PORT = 3000;

  // HTTP Status Codes
  HTTP_OK = 200;
  HTTP_FOUND = 302;
  HTTP_ACCEPTED = 202;
  HTTP_NO_CONTENT = 204;
  HTTP_BAD_REQUEST = 400;
  HTTP_UNAUTHORIZED = 401;
  HTTP_NOT_FOUND = 404;
  HTTP_METHOD_NOT_ALLOWED = 405;
  HTTP_NOT_ACCEPTABLE = 406;
  HTTP_FORBIDDEN = 403;

  // CORS Max Age (24 hours in seconds)
  CORS_MAX_AGE = 86400;

  // Auth code lifetime: 10 minutes
  AUTH_CODE_LIFETIME = 10 / (24 * 60);

  // JSON-RPC 2.0 Error Codes
  JSONRPC_PARSE_ERROR = -32700;
  JSONRPC_INVALID_REQUEST = -32600;
  JSONRPC_METHOD_NOT_FOUND = -32601;
  JSONRPC_INVALID_PARAMS = -32602;
  JSONRPC_INTERNAL_ERROR = -32603;

  // SSE Message Format
  SSE_EVENT_PREFIX = 'event: ';
  SSE_DATA_PREFIX = 'data: ';
  SSE_ID_PREFIX = 'id: ';
  SSE_MESSAGE_TERMINATOR = #10#10;

  // OAuth endpoint paths
  OAUTH_WELL_KNOWN_PATH      = '/.well-known/oauth-authorization-server';
  OAUTH_PROTECTED_RESOURCE   = '/.well-known/oauth-protected-resource';
  OAUTH_AUTHORIZE_PATH       = '/authorize';
  OAUTH_TOKEN_PATH           = '/token';
  OAUTH_REGISTER_PATH        = '/register';

  // Simple HTML login form — %s slots: error_html, client_id, redirect_uri, code_challenge, state
  AUTH_FORM_HTML =
    '<!DOCTYPE html><html><head><title>NexusDB MCP &ndash; Authorize</title>' +
    '<style>body{font-family:sans-serif;max-width:420px;margin:80px auto;padding:20px}' +
    'h2{margin-bottom:6px}p{color:#555;margin-top:0}' +
    'input[type=password]{width:100%%;padding:9px;margin:8px 0 16px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}' +
    'button{background:#0066cc;color:#fff;border:none;padding:10px 24px;cursor:pointer;border-radius:4px;font-size:14px}' +
    '.err{color:#c00;margin:8px 0}</style></head>' +
    '<body><h2>NexusDB MCP Authorization</h2>' +
    '<p>An application is requesting access to your NexusDB MCP server.</p>%s' +
    '<form method="post" action="/authorize">' +
    '<input type="hidden" name="client_id" value="%s">' +
    '<input type="hidden" name="redirect_uri" value="%s">' +
    '<input type="hidden" name="code_challenge" value="%s">' +
    '<input type="hidden" name="code_challenge_method" value="S256">' +
    '<input type="hidden" name="state" value="%s">' +
    '<label>Password:<br><input type="password" name="password" autofocus></label>' +
    '<button type="submit">Authorize</button>' +
    '</form></body></html>';

{ TMCPIdHTTPServer }

constructor TMCPIdHTTPServer.Create(Owner: TComponent);
begin
  inherited Create(Owner);
  FPort := DEFAULT_MCP_PORT;
  FActive := False;
  FEventIDCounter := 0;
  FJsonRpcProcessor := nil;
  FAuthCodes := TDictionary<string, TAuthCodeEntry>.Create;
  FAuthCodesLock := TCriticalSection.Create;

  FHTTPServer := TIdHTTPServer.Create(Self);
  FHTTPServer.KeepAlive := True;
  FHTTPServer.OnCommandGet := HandleHTTPRequest;
  FHTTPServer.OnCommandOther := HandleHTTPRequest;
  FHTTPServer.OnQuerySSLPort := HandleQuerySSLPort;
  FSSLHandler := nil;
end;

destructor TMCPIdHTTPServer.Destroy;
begin
  if FActive then
    Stop;
  FHTTPServer.Free;
  if Assigned(FSSLHandler) then
    FSSLHandler.Free;
  FJsonRpcProcessor.Free;
  FAuthCodes.Free;
  FAuthCodesLock.Free;
  inherited;
end;

procedure TMCPIdHTTPServer.Start;
begin
  if FActive then
    Exit;

  if not Assigned(FManagerRegistry) then
    raise Exception.Create('Manager registry not assigned');

  FJsonRpcProcessor := TMCPJsonRpcProcessor.Create(FManagerRegistry);

  if Assigned(FSettings) then
  begin
    FPort := Word(FSettings.Port);

    if FSettings.SSLEnabled then
      ConfigureSSL;
  end;

  FHTTPServer.DefaultPort := FPort;
  FHTTPServer.Active := True;
  FActive := True;

  TLogger.Info('MCP Server started on ' + FSettings.Protocol + '://' + FSettings.Host + ':' + IntToStr(FPort));
end;

procedure TMCPIdHTTPServer.Stop;
begin
  if not FActive then
    Exit;

  FHTTPServer.Active := False;
  FActive := False;
  TLogger.Info('MCP Server stopped');
end;

procedure TMCPIdHTTPServer.HandleHTTPRequest(Context: TIdContext;
  RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
var
  RequestPath: string;
  AuthHeader: string;
  BearerToken: string;
  I: Integer;
begin
  TServerStatusResource.ConnectionOpened;
  try
    TServerStatusResource.IncrementRequestCount;

    RequestPath := RequestInfo.Document;

    // OAuth discovery endpoints are always public — route before CORS check
    if RequestPath = OAUTH_WELL_KNOWN_PATH then
    begin
      ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';
      HandleWellKnownOAuth(RequestInfo, ResponseInfo);
      Exit;
    end;

    // RFC 9728: /.well-known/oauth-protected-resource/{resource-path}
    if RequestPath.StartsWith(OAUTH_PROTECTED_RESOURCE) then
    begin
      ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';
      HandleProtectedResourceMetadata(RequestInfo, ResponseInfo);
      Exit;
    end;

    // OAuth flow endpoints manage their own CORS — route before the CORS check
    if RequestPath = OAUTH_AUTHORIZE_PATH then
    begin
      if Assigned(FSettings) and FSettings.OAuthEnabled then
        HandleAuthorize(RequestInfo, ResponseInfo)
      else
      begin
        ResponseInfo.ResponseNo := HTTP_NOT_FOUND;
        ResponseInfo.ResponseText := 'Not Found';
      end;
      Exit;
    end;

    if RequestPath = OAUTH_TOKEN_PATH then
    begin
      if Assigned(FSettings) and FSettings.OAuthEnabled then
        HandleToken(RequestInfo, ResponseInfo)
      else
      begin
        ResponseInfo.ResponseNo := HTTP_NOT_FOUND;
        ResponseInfo.ResponseText := 'Not Found';
      end;
      Exit;
    end;

    if RequestPath = OAUTH_REGISTER_PATH then
    begin
      if Assigned(FSettings) and FSettings.OAuthEnabled then
        HandleRegister(RequestInfo, ResponseInfo)
      else
      begin
        ResponseInfo.ResponseNo := HTTP_NOT_FOUND;
        ResponseInfo.ResponseText := 'Not Found';
      end;
      Exit;
    end;

    if not VerifyAndSetCORSHeaders(RequestInfo, ResponseInfo) then
      Exit;

    // Only handle requests to the configured MCP endpoint
    if RequestPath <> FSettings.Endpoint then
    begin
      ResponseInfo.ResponseNo := HTTP_NOT_FOUND;
      ResponseInfo.ResponseText := 'Not Found';
      Exit;
    end;

    // Validate Bearer token on the MCP endpoint when OAuth is enabled
    if Assigned(FSettings) and FSettings.OAuthEnabled and (RequestInfo.Command <> 'OPTIONS') then
    begin
      // Read from X-MCP-Authorization (nginx renames Authorization to avoid Indy's
      // built-in auth interception which returns 401 before our handler is called).
      // Fall back to Authorization for direct connections that bypass nginx.
      AuthHeader := '';
      for I := 0 to RequestInfo.RawHeaders.Count - 1 do
      begin
        var RawLine := RequestInfo.RawHeaders[I];
        var ColonPos := RawLine.IndexOf(':');
        if ColonPos > 0 then
        begin
          var HdrName := RawLine.Substring(0, ColonPos).Trim.ToLower;
          if HdrName = 'x-mcp-authorization' then
          begin
            AuthHeader := RawLine.Substring(ColonPos + 1).Trim;
            Break;
          end
          else if (HdrName = 'authorization') and (AuthHeader = '') then
            AuthHeader := RawLine.Substring(ColonPos + 1).Trim;
        end;
      end;

      if AuthHeader.StartsWith('Bearer ', True) then
        BearerToken := AuthHeader.Substring(7).Trim
      else
        BearerToken := '';

      TLogger.Info(Format('MCP auth: Authorization header length=%d, token length=%d',
        [Length(AuthHeader), Length(BearerToken)]));

      if not ValidateBearerToken(BearerToken) then
      begin
        ResponseInfo.ResponseNo := HTTP_UNAUTHORIZED;
        ResponseInfo.ResponseText := 'Unauthorized';
        ResponseInfo.CustomHeaders.Values['WWW-Authenticate'] :=
          'Bearer realm="' + GetRequestBaseURL(RequestInfo) + '"';
        ResponseInfo.ContentType := 'application/json';
        ResponseInfo.ContentText := '{"error":"invalid_token"}';
        TLogger.Warning('Rejected unauthenticated MCP request from: ' + RequestInfo.RemoteIP);
        Exit;
      end;
    end;

    if RequestInfo.Command = 'OPTIONS' then
      HandleOptionsRequest(ResponseInfo)
    else if RequestInfo.CommandType = hcGET then
      HandleGetRequest(RequestInfo, ResponseInfo)
    else if RequestInfo.CommandType = hcPOST then
      HandlePostRequest(RequestInfo, ResponseInfo)
    else
    begin
      ResponseInfo.ResponseNo := HTTP_METHOD_NOT_ALLOWED;
      ResponseInfo.ResponseText := 'Method Not Allowed';
    end;
  finally
    TServerStatusResource.ConnectionClosed;
  end;
end;

function TMCPIdHTTPServer.VerifyAndSetCORSHeaders(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo): Boolean;
begin
  Result := True;

  if not Assigned(FSettings) or not FSettings.CorsEnabled then
    Exit;

  var Origin := RequestInfo.RawHeaders.Values['Origin'];
  var AllowedOrigin: string := '*';

  if (FSettings.CorsAllowedOrigins <> '*') and (Origin <> '') then
  begin
    var OriginsList := TStringList.Create;
    try
      OriginsList.CommaText := FSettings.CorsAllowedOrigins;
      var Found := False;

      for var CurrentOrigin in OriginsList do
      begin
        if SameText(Trim(CurrentOrigin), Origin) then
        begin
          AllowedOrigin := Origin;
          Found := True;
          Break;
        end;
      end;

      if not Found then
      begin
        Result := False;
        ResponseInfo.ResponseNo := HTTP_FORBIDDEN;
        ResponseInfo.ResponseText := 'Forbidden - Origin not allowed';
        TLogger.Info('CORS blocked origin: ' + Origin);
        Exit;
      end;
    finally
      OriginsList.Free;
    end;
  end;

  ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := AllowedOrigin;
  ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Methods'] := 'POST, GET, OPTIONS';
  ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Headers'] :=
    'Content-Type, Mcp-Session-Id, Authorization';
  ResponseInfo.CustomHeaders.Values['Access-Control-Max-Age'] := CORS_MAX_AGE.ToString;
end;

procedure TMCPIdHTTPServer.HandleOptionsRequest(ResponseInfo: TIdHTTPResponseInfo);
begin
  ResponseInfo.ResponseNo := HTTP_OK;
  ResponseInfo.ResponseText := 'OK';
end;

procedure TMCPIdHTTPServer.HandleGetRequest(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
begin
  var AcceptHeader := RequestInfo.RawHeaders.Values['Accept'];

  if AcceptsSSE(AcceptHeader) then
  begin
    TLogger.Debug('Received GET request - opening SSE stream for server-initiated messages');

    ResponseInfo.ContentType := 'text/event-stream';
    ResponseInfo.CharSet := 'utf-8';
    ResponseInfo.CustomHeaders.Values['Cache-Control'] := 'no-cache';
    ResponseInfo.CustomHeaders.Values['Connection'] := 'keep-alive';
    ResponseInfo.CustomHeaders.Values['X-Accel-Buffering'] := 'no';

    var SessionID := RequestInfo.RawHeaders.Values['Mcp-Session-Id'];
    if SessionID <> '' then
      ResponseInfo.CustomHeaders.Values['Mcp-Session-Id'] := SessionID;

    ResponseInfo.ResponseNo := HTTP_OK;
    ResponseInfo.ContentText := '';

    TLogger.Debug('SSE stream opened (no server-initiated messages to send)');
  end
  else
  begin
    TLogger.Info('Received GET request - returning endpoint info');

    ResponseInfo.ContentType := 'application/json';
    ResponseInfo.CustomHeaders.Values['Cache-Control'] := 'no-cache';
    ResponseInfo.CustomHeaders.Values['Connection'] := 'keep-alive';

    ResponseInfo.ContentText := '{"url": "' + FSettings.Protocol + '://' + FSettings.Host + ':' + IntToStr(FPort) +
                    FSettings.Endpoint + '", "transport": "' + FSettings.Protocol + '"}';

    ResponseInfo.ResponseNo := HTTP_OK;
  end;
end;

procedure TMCPIdHTTPServer.HandlePostRequest(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
begin
  var RequestBody := '';
  if Assigned(RequestInfo.PostStream) and (RequestInfo.PostStream.Size > 0) then
  begin
    RequestInfo.PostStream.Position := 0;
    RequestBody := ReadStringFromStream(RequestInfo.PostStream, -1, IndyTextEncoding_UTF8);
  end;

  TLogger.Info('Request: ' + RequestBody);

  var SessionID := RequestInfo.RawHeaders.Values['Mcp-Session-Id'];
  if SessionID <> '' then
    TLogger.Info('Session ID from header: ' + SessionID);

  var AcceptHeader := RequestInfo.RawHeaders.Values['Accept'];

  var JSONRequest: TJSONValue := nil;
  try
    JSONRequest := TJSONObject.ParseJSONValue(RequestBody);

    if Assigned(JSONRequest) and IsRequestOnlyNotificationsOrResponses(JSONRequest) then
    begin
      TLogger.Info('Request contains only notifications/responses, returning 202 Accepted');
      ResponseInfo.ResponseNo := HTTP_ACCEPTED;

      if SessionID <> '' then
        ResponseInfo.CustomHeaders.Values['Mcp-Session-Id'] := SessionID;

      Exit;
    end;

    if AcceptsSSE(AcceptHeader) then
      HandlePostRequestSSE(RequestInfo, ResponseInfo, RequestBody, SessionID)
    else
      HandlePostRequestJSON(RequestInfo, ResponseInfo, RequestBody, SessionID);

  finally
    JSONRequest.Free;
  end;
end;

procedure TMCPIdHTTPServer.ConfigureSSL;
begin
  if not TFile.Exists(FSettings.SSLCertFile) then
  begin
    TLogger.Error('SSL Certificate file not found: ' + FSettings.SSLCertFile);
    raise Exception.Create('SSL Certificate file not found: ' + FSettings.SSLCertFile);
  end;

  if not TFile.Exists(FSettings.SSLKeyFile) then
  begin
    TLogger.Error('SSL Key file not found: ' + FSettings.SSLKeyFile);
    raise Exception.Create('SSL Key file not found: ' + FSettings.SSLKeyFile);
  end;

  {$IFDEF USE_TAURUS_TLS}
  FSSLHandler := TTaurusTLSServerIOHandler.Create(Self);
  FSSLHandler.DefaultCert.PublicKey := FSettings.SSLCertFile;
  FSSLHandler.DefaultCert.PrivateKey := FSettings.SSLKeyFile;
  {$ELSE}
  FSSLHandler := TIdServerIOHandlerSSLOpenSSL.Create(Self);
  FSSLHandler.SSLOptions.CertFile := FSettings.SSLCertFile;
  FSSLHandler.SSLOptions.KeyFile := FSettings.SSLKeyFile;

  if (FSettings.SSLRootCertFile <> '') and TFile.Exists(FSettings.SSLRootCertFile) then
    FSSLHandler.SSLOptions.RootCertFile := FSettings.SSLRootCertFile;

  FSSLHandler.SSLOptions.Method := sslvTLSv1_2;
  FSSLHandler.SSLOptions.SSLVersions := [sslvTLSv1, sslvTLSv1_1, sslvTLSv1_2];
  FSSLHandler.SSLOptions.Mode := sslmServer;
  {$ENDIF}

  FHTTPServer.IOHandler := FSSLHandler;

  TLogger.Info('SSL configured successfully');
  TLogger.Info('Certificate: ' + FSettings.SSLCertFile);
  TLogger.Info('Private Key: ' + FSettings.SSLKeyFile);
  if FSettings.SSLRootCertFile <> '' then
    TLogger.Info('Root Certificate: ' + FSettings.SSLRootCertFile);
end;

procedure TMCPIdHTTPServer.HandleQuerySSLPort(APort: Word; var VUseSSL: Boolean);
begin
  VUseSSL := FSettings.SSLEnabled and (APort = FPort);
end;

function TMCPIdHTTPServer.GetNextEventID: string;
begin
  Inc(FEventIDCounter);
  Result := IntToStr(FEventIDCounter);
end;

function TMCPIdHTTPServer.AcceptsSSE(const AcceptHeader: string): Boolean;
begin
  Result := Pos('text/event-stream', AcceptHeader) > 0;
end;

function TMCPIdHTTPServer.IsRequestOnlyNotificationsOrResponses(JSONRequest: TJSONValue): Boolean;
begin
  if JSONRequest is TJSONObject then
  begin
    var Obj := JSONRequest as TJSONObject;
    var MethodValue := Obj.GetValue('method');
    var IdValue := Obj.GetValue('id');
    var ResultValue := Obj.GetValue('result');
    var ErrorValue := Obj.GetValue('error');

    if Assigned(MethodValue) and not Assigned(IdValue) then
      Exit(True);

    if Assigned(ResultValue) or Assigned(ErrorValue) then
      Exit(True);

    Result := False;
  end
  else if JSONRequest is TJSONArray then
  begin
    var Arr := JSONRequest as TJSONArray;
    Result := True;
    for var I := 0 to Arr.Count - 1 do
    begin
      if not IsRequestOnlyNotificationsOrResponses(Arr.Items[I]) then
      begin
        Result := False;
        Break;
      end;
    end;
  end
  else
    Result := False;
end;

procedure TMCPIdHTTPServer.HandlePostRequestSSE(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo; const RequestBody: string; const SessionID: string);
begin
  TLogger.Info('Handling POST request with SSE stream');

  ResponseInfo.ContentType := 'text/event-stream';
  ResponseInfo.CharSet := 'utf-8';
  ResponseInfo.CustomHeaders.Values['Cache-Control'] := 'no-cache';
  ResponseInfo.CustomHeaders.Values['Connection'] := 'keep-alive';
  ResponseInfo.CustomHeaders.Values['X-Accel-Buffering'] := 'no';

  if SessionID <> '' then
    ResponseInfo.CustomHeaders.Values['Mcp-Session-Id'] := SessionID;

  var JSONResponse := FJsonRpcProcessor.ProcessRequest(RequestBody, SessionID);

  if JSONResponse <> '' then
  begin
    var EventID := GetNextEventID;
    var SSEMessage := '';

    if EventID <> '' then
      SSEMessage := SSEMessage + SSE_ID_PREFIX + EventID + #10;

    SSEMessage := SSEMessage + SSE_EVENT_PREFIX + 'message' + #10;
    SSEMessage := SSEMessage + SSE_DATA_PREFIX + JSONResponse + SSE_MESSAGE_TERMINATOR;

    ResponseInfo.ContentText := SSEMessage;
    TLogger.Info('SSE response prepared with event ID: ' + EventID);
  end
  else
  begin
    ResponseInfo.ContentText := '';
  end;

  ResponseInfo.ResponseNo := HTTP_OK;
end;

procedure TMCPIdHTTPServer.HandlePostRequestJSON(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo; const RequestBody: string; const SessionID: string);
begin
  TLogger.Info('Handling POST request with JSON response');

  var ResponseBody := FJsonRpcProcessor.ProcessRequest(RequestBody, SessionID);

  if ResponseBody = '' then
  begin
    ResponseInfo.ResponseNo := HTTP_NO_CONTENT;
    Exit;
  end;

  ResponseInfo.ContentType := 'application/json';
  ResponseInfo.CustomHeaders.Values['Connection'] := 'keep-alive';

  if (SessionID = '') and (Pos('"sessionId"', ResponseBody) > 0) then
  begin
    var ResponseJSON := TJSONObject.ParseJSONValue(ResponseBody) as TJSONObject;
    try
      var ResultObj := ResponseJSON.GetValue('result') as TJSONObject;
      if Assigned(ResultObj) then
      begin
        var SessionValue := ResultObj.GetValue('sessionId');
        if Assigned(SessionValue) then
          ResponseInfo.CustomHeaders.Values['Mcp-Session-Id'] := SessionValue.Value;
      end;
    finally
      ResponseJSON.Free;
    end;
  end
  else if SessionID <> '' then
    ResponseInfo.CustomHeaders.Values['Mcp-Session-Id'] := SessionID;

  ResponseInfo.ContentStream := TStringStream.Create(ResponseBody, TEncoding.UTF8);
  ResponseInfo.FreeContentStream := True;
  ResponseInfo.ResponseNo := HTTP_OK;

  TLogger.Info('Response: ' + ResponseBody);
end;

// ── OAuth helpers ────────────────────────────────────────────────────────────

function TMCPIdHTTPServer.Base64URLEncode(const Bytes: TBytes): string;
begin
  Result := TNetEncoding.Base64.EncodeBytesToString(Bytes);
  // Strip line breaks that Delphi's Base64 encoder adds every 76 chars —
  // newlines in a JWT would break Authorization header transmission
  Result := Result.Replace(#13#10, '', [rfReplaceAll])
                  .Replace(#13,    '', [rfReplaceAll])
                  .Replace(#10,    '', [rfReplaceAll])
                  .Replace('+', '-', [rfReplaceAll])
                  .Replace('/', '_', [rfReplaceAll])
                  .Replace('=', '',  [rfReplaceAll]);
end;

function TMCPIdHTTPServer.Base64URLDecode(const S: string): TBytes;
var
  Padded: string;
begin
  Padded := S.Replace('-', '+', [rfReplaceAll]).Replace('_', '/', [rfReplaceAll]);
  case Length(Padded) mod 4 of
    2: Padded := Padded + '==';
    3: Padded := Padded + '=';
  end;
  Result := TNetEncoding.Base64.DecodeStringToBytes(Padded);
end;

function TMCPIdHTTPServer.ParseFormParams(const Body: string): TDictionary<string, string>;
var
  Pairs: TArray<string>;
  Parts: TArray<string>;
begin
  Result := TDictionary<string, string>.Create;
  Pairs := Body.Split(['&']);
  for var Pair in Pairs do
  begin
    Parts := Pair.Split(['='], 2);
    if Length(Parts) = 2 then
      Result.AddOrSetValue(TIdURI.URLDecode(Parts[0]), TIdURI.URLDecode(Parts[1]));
  end;
end;

function TMCPIdHTTPServer.GetRequestBaseURL(RequestInfo: TIdHTTPRequestInfo): string;
var
  Proto, Host: string;
begin
  // Honour nginx X-Forwarded-Proto so we advertise the public https:// URL
  Proto := RequestInfo.RawHeaders.Values['X-Forwarded-Proto'];
  if Proto = '' then
  begin
    if Assigned(FSettings) and FSettings.SSLEnabled then Proto := 'https'
    else Proto := 'http';
  end;
  Host := RequestInfo.RawHeaders.Values['Host'];
  if Host = '' then
  begin
    if Assigned(FSettings) then
      Host := FSettings.Host + ':' + IntToStr(FSettings.Port)
    else
      Host := 'localhost:' + IntToStr(FPort);
  end;
  Result := Proto + '://' + Host;
end;

function TMCPIdHTTPServer.GenerateAuthCode: string;
var
  G: TGUID;
begin
  CreateGUID(G);
  Result := GUIDToString(G).Replace('{', '', [rfReplaceAll])
                            .Replace('}', '', [rfReplaceAll])
                            .Replace('-', '', [rfReplaceAll])
                            .ToLower;
end;

procedure TMCPIdHTTPServer.CleanExpiredAuthCodes;
var
  Expired: TList<string>;
begin
  Expired := TList<string>.Create;
  try
    for var Pair in FAuthCodes do
      if Now > Pair.Value.ExpiresAt then
        Expired.Add(Pair.Key);
    for var Key in Expired do
      FAuthCodes.Remove(Key);
  finally
    Expired.Free;
  end;
end;

function TMCPIdHTTPServer.GenerateJWT: string;
var
  Header, Payload, SignInput: string;
  NowUnix, ExpUnix: Int64;
  KeyBytes, SigBytes: TBytes;
begin
  NowUnix := DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now));
  ExpUnix  := NowUnix + FSettings.OAuthTokenExpiry;

  Header  := '{"alg":"HS256","typ":"JWT"}';
  Payload := Format('{"iat":%d,"exp":%d,"iss":"nxmcp"}', [NowUnix, ExpUnix]);

  var HeaderEnc  := Base64URLEncode(TEncoding.UTF8.GetBytes(Header));
  var PayloadEnc := Base64URLEncode(TEncoding.UTF8.GetBytes(Payload));
  SignInput := HeaderEnc + '.' + PayloadEnc;

  KeyBytes := TEncoding.UTF8.GetBytes(FSettings.OAuthTokenSecret);
  SigBytes := THashSHA2.GetHMACAsBytes(TEncoding.UTF8.GetBytes(SignInput), KeyBytes);

  Result := SignInput + '.' + Base64URLEncode(SigBytes);
end;

function TMCPIdHTTPServer.ValidateBearerToken(const Token: string): Boolean;
var
  Parts: TArray<string>;
  SignInput: string;
  KeyBytes, SigBytes, ExpectedSig: TBytes;
  PayloadStr: string;
  PayloadJSON: TJSONObject;
  ExpValue: Int64;
begin
  Result := False;

  if not Assigned(FSettings) or (FSettings.OAuthTokenSecret = '') then
    Exit;

  Parts := Token.Split(['.']);
  if Length(Parts) <> 3 then
  begin
    TLogger.Warning('ValidateBearerToken: wrong number of parts: ' + IntToStr(Length(Parts)));
    Exit;
  end;

  // Verify HMAC-SHA256 signature
  SignInput    := Parts[0] + '.' + Parts[1];
  KeyBytes     := TEncoding.UTF8.GetBytes(FSettings.OAuthTokenSecret);
  ExpectedSig  := THashSHA2.GetHMACAsBytes(TEncoding.UTF8.GetBytes(SignInput), KeyBytes);
  SigBytes     := Base64URLDecode(Parts[2]);

  if (Length(SigBytes) = 0) or (Length(SigBytes) <> Length(ExpectedSig)) then
  begin
    TLogger.Warning(Format('ValidateBearerToken: signature length mismatch: got %d, expected %d',
      [Length(SigBytes), Length(ExpectedSig)]));
    Exit;
  end;
  if not CompareMem(@SigBytes[0], @ExpectedSig[0], Length(ExpectedSig)) then
  begin
    TLogger.Warning('ValidateBearerToken: signature mismatch');
    Exit;
  end;

  // Verify expiry claim
  PayloadStr  := TEncoding.UTF8.GetString(Base64URLDecode(Parts[1]));
  PayloadJSON := TJSONObject.ParseJSONValue(PayloadStr) as TJSONObject;
  if not Assigned(PayloadJSON) then
  begin
    TLogger.Warning('ValidateBearerToken: could not parse payload');
    Exit;
  end;
  try
    var ExpVal := PayloadJSON.GetValue('exp');
    if not Assigned(ExpVal) then
    begin
      TLogger.Warning('ValidateBearerToken: no exp claim');
      Exit;
    end;
    ExpValue := StrToInt64(ExpVal.Value);
    var NowUnix := DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now));
    if NowUnix > ExpValue then
    begin
      TLogger.Warning(Format('ValidateBearerToken: token expired (now=%d, exp=%d)', [NowUnix, ExpValue]));
      Exit;
    end;
    TLogger.Info('ValidateBearerToken: token valid');
    Result := True;
  finally
    PayloadJSON.Free;
  end;
end;

function TMCPIdHTTPServer.GetParam(Params: TDictionary<string, string>; const Key: string): string;
begin
  if not Params.TryGetValue(Key, Result) then
    Result := '';
end;

function TMCPIdHTTPServer.HTMLEncode(const S: string): string;
begin
  Result := S.Replace('&',  '&amp;',  [rfReplaceAll])
             .Replace('<',  '&lt;',   [rfReplaceAll])
             .Replace('>',  '&gt;',   [rfReplaceAll])
             .Replace('"',  '&quot;', [rfReplaceAll])
             .Replace('''', '&#39;',  [rfReplaceAll]);
end;

// ── OAuth endpoint handlers ──────────────────────────────────────────────────

procedure TMCPIdHTTPServer.HandleWellKnownOAuth(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
var
  Base: string;
  Meta: TJSONObject;
begin
  Base := GetRequestBaseURL(RequestInfo);
  Meta := TJSONObject.Create;
  try
    Meta.AddPair('issuer',                 Base);
    Meta.AddPair('authorization_endpoint', Base + OAUTH_AUTHORIZE_PATH);
    Meta.AddPair('token_endpoint',         Base + OAUTH_TOKEN_PATH);

    var RespTypes := TJSONArray.Create;
    RespTypes.Add('code');
    Meta.AddPair('response_types_supported', RespTypes);

    var GrantTypes := TJSONArray.Create;
    GrantTypes.Add('authorization_code');
    Meta.AddPair('grant_types_supported', GrantTypes);

    var ChallengeMethods := TJSONArray.Create;
    ChallengeMethods.Add('S256');
    Meta.AddPair('code_challenge_methods_supported', ChallengeMethods);

    var AuthMethods := TJSONArray.Create;
    AuthMethods.Add('none');
    Meta.AddPair('token_endpoint_auth_methods_supported', AuthMethods);
    Meta.AddPair('registration_endpoint', Base + OAUTH_REGISTER_PATH);

    ResponseInfo.ContentType := 'application/json';
    ResponseInfo.ContentText := Meta.ToJSON;
    ResponseInfo.ResponseNo  := HTTP_OK;
  finally
    Meta.Free;
  end;
end;

procedure TMCPIdHTTPServer.HandleProtectedResourceMetadata(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
var
  Base: string;
  Meta: TJSONObject;
  AuthServers: TJSONArray;
  BearerMethods: TJSONArray;
begin
  Base := GetRequestBaseURL(RequestInfo);
  Meta := TJSONObject.Create;
  try
    Meta.AddPair('resource', Base + FSettings.Endpoint);
    AuthServers := TJSONArray.Create;
    AuthServers.Add(Base);
    Meta.AddPair('authorization_servers', AuthServers);
    BearerMethods := TJSONArray.Create;
    BearerMethods.Add('header');
    Meta.AddPair('bearer_methods_supported', BearerMethods);

    ResponseInfo.ContentType := 'application/json';
    ResponseInfo.ContentText := Meta.ToJSON;
    ResponseInfo.ResponseNo  := HTTP_OK;
  finally
    Meta.Free;
  end;
end;

procedure TMCPIdHTTPServer.HandleRegister(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
var
  RequestJSON, ResponseJSON: TJSONObject;
  Body: string;
  ClientID: string;
  RedirectURIs: TJSONValue;
begin
  // RFC 7591 dynamic client registration — accept any client, return a client_id
  // Real auth is handled by the password form in /authorize, not client credentials
  ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';

  if RequestInfo.CommandType <> hcPOST then
  begin
    ResponseInfo.ResponseNo := HTTP_METHOD_NOT_ALLOWED;
    Exit;
  end;

  Body := '';
  if Assigned(RequestInfo.PostStream) and (RequestInfo.PostStream.Size > 0) then
  begin
    RequestInfo.PostStream.Position := 0;
    Body := ReadStringFromStream(RequestInfo.PostStream, -1, IndyTextEncoding_UTF8);
  end;

  ClientID := GenerateAuthCode; // reuse GUID generator for a unique client_id

  ResponseJSON := TJSONObject.Create;
  try
    ResponseJSON.AddPair('client_id', ClientID);
    ResponseJSON.AddPair('client_id_issued_at', TJSONNumber.Create(
      DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now))));
    ResponseJSON.AddPair('token_endpoint_auth_method', 'none');

    // Echo back redirect_uris and grant_types from the request if present
    RequestJSON := TJSONObject.ParseJSONValue(Body) as TJSONObject;
    if Assigned(RequestJSON) then
    try
      RedirectURIs := RequestJSON.GetValue('redirect_uris');
      if Assigned(RedirectURIs) then
        ResponseJSON.AddPair('redirect_uris', RedirectURIs.Clone as TJSONValue);
      var GrantTypes := RequestJSON.GetValue('grant_types');
      if Assigned(GrantTypes) then
        ResponseJSON.AddPair('grant_types', GrantTypes.Clone as TJSONValue);
    finally
      RequestJSON.Free;
    end;

    ResponseInfo.ResponseNo  := 201;
    ResponseInfo.ResponseText := 'Created';
    ResponseInfo.ContentType := 'application/json';
    ResponseInfo.CustomHeaders.Values['Cache-Control'] := 'no-store';
    ResponseInfo.ContentText := ResponseJSON.ToJSON;
    TLogger.Info('OAuth: registered client_id=' + ClientID);
  finally
    ResponseJSON.Free;
  end;
end;

procedure TMCPIdHTTPServer.HandleAuthorize(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
var
  Params: TDictionary<string, string>;
  ClientID, RedirectURI, CodeChallenge, State, Password: string;
  Entry: TAuthCodeEntry;
  AuthCode, Location: string;
begin
  if RequestInfo.CommandType = hcGET then
  begin
    Params := ParseFormParams(RequestInfo.QueryParams);
    try
      ClientID      := GetParam(Params, 'client_id');
      RedirectURI   := GetParam(Params, 'redirect_uri');
      CodeChallenge := GetParam(Params, 'code_challenge');
      State         := GetParam(Params, 'state');
    finally
      Params.Free;
    end;

    if (RedirectURI = '') or (CodeChallenge = '') then
    begin
      ResponseInfo.ResponseNo  := HTTP_BAD_REQUEST;
      ResponseInfo.ContentText := 'Missing required parameters: redirect_uri and code_challenge';
      Exit;
    end;

    ResponseInfo.ContentType := 'text/html; charset=utf-8';
    ResponseInfo.ContentText := Format(AUTH_FORM_HTML, ['',
      HTMLEncode(ClientID), HTMLEncode(RedirectURI),
      HTMLEncode(CodeChallenge), HTMLEncode(State)]);
    ResponseInfo.ResponseNo := HTTP_OK;
  end
  else if RequestInfo.CommandType = hcPOST then
  begin
    var Body := RequestInfo.FormParams;
    if (Body = '') and Assigned(RequestInfo.PostStream) and (RequestInfo.PostStream.Size > 0) then
    begin
      RequestInfo.PostStream.Position := 0;
      Body := ReadStringFromStream(RequestInfo.PostStream, -1, IndyTextEncoding_UTF8);
    end;

    Params := ParseFormParams(Body);
    try
      ClientID      := GetParam(Params, 'client_id');
      RedirectURI   := GetParam(Params, 'redirect_uri');
      CodeChallenge := GetParam(Params, 'code_challenge');
      State         := GetParam(Params, 'state');
      Password      := GetParam(Params, 'password');
    finally
      Params.Free;
    end;

    TLogger.Info(Format('OAuth: password check - received %d chars, stored %d chars, body %d chars',
      [Length(Password), Length(FSettings.OAuthPassword), Length(Body)]));

    if Password <> FSettings.OAuthPassword then
    begin
      ResponseInfo.ContentType := 'text/html; charset=utf-8';
      ResponseInfo.ContentText := Format(AUTH_FORM_HTML,
        ['<p class="err">Incorrect password. Please try again.</p>',
         HTMLEncode(ClientID), HTMLEncode(RedirectURI),
         HTMLEncode(CodeChallenge), HTMLEncode(State)]);
      ResponseInfo.ResponseNo := HTTP_OK;
      TLogger.Warning('Failed OAuth login attempt from: ' + RequestInfo.RemoteIP);
      Exit;
    end;

    AuthCode := GenerateAuthCode;
    Entry.CodeChallenge := CodeChallenge;
    Entry.RedirectURI   := RedirectURI;
    Entry.State         := State;
    Entry.ExpiresAt     := Now + AUTH_CODE_LIFETIME;

    FAuthCodesLock.Enter;
    try
      CleanExpiredAuthCodes;
      FAuthCodes.AddOrSetValue(AuthCode, Entry);
    finally
      FAuthCodesLock.Leave;
    end;

    Location := RedirectURI + '?code=' + AuthCode;
    if State <> '' then
      Location := Location + '&state=' + TIdURI.ParamsEncode(State);

    ResponseInfo.ResponseNo   := HTTP_FOUND;
    ResponseInfo.ResponseText := 'Found';
    ResponseInfo.CustomHeaders.Values['Location'] := Location;
    TLogger.Info('OAuth: issued auth code for client_id=' + ClientID);
  end
  else
    ResponseInfo.ResponseNo := HTTP_METHOD_NOT_ALLOWED;
end;

procedure TMCPIdHTTPServer.HandleToken(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
var
  Body: string;
  Params: TDictionary<string, string>;
  Code, CodeVerifier, GrantType: string;
  Entry: TAuthCodeEntry;
  ComputedChallenge: string;
  TokenJSON: TJSONObject;
begin
  // Token endpoint always allows any origin so clients can call it cross-origin
  ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';

  if RequestInfo.CommandType <> hcPOST then
  begin
    ResponseInfo.ResponseNo := HTTP_METHOD_NOT_ALLOWED;
    Exit;
  end;

  Body := RequestInfo.FormParams;
  if (Body = '') and Assigned(RequestInfo.PostStream) and (RequestInfo.PostStream.Size > 0) then
  begin
    RequestInfo.PostStream.Position := 0;
    Body := ReadStringFromStream(RequestInfo.PostStream, -1, IndyTextEncoding_UTF8);
  end;

  Params := ParseFormParams(Body);
  try
    GrantType   := GetParam(Params, 'grant_type');
    Code        := GetParam(Params, 'code');
    CodeVerifier := GetParam(Params, 'code_verifier');
  finally
    Params.Free;
  end;

  if GrantType <> 'authorization_code' then
  begin
    ResponseInfo.ResponseNo  := HTTP_BAD_REQUEST;
    ResponseInfo.ContentType := 'application/json';
    ResponseInfo.ContentText := '{"error":"unsupported_grant_type"}';
    Exit;
  end;

  FAuthCodesLock.Enter;
  try
    if not FAuthCodes.TryGetValue(Code, Entry) then
    begin
      ResponseInfo.ResponseNo  := HTTP_BAD_REQUEST;
      ResponseInfo.ContentType := 'application/json';
      ResponseInfo.ContentText := '{"error":"invalid_grant"}';
      Exit;
    end;

    if Now > Entry.ExpiresAt then
    begin
      FAuthCodes.Remove(Code);
      ResponseInfo.ResponseNo  := HTTP_BAD_REQUEST;
      ResponseInfo.ContentType := 'application/json';
      ResponseInfo.ContentText := '{"error":"invalid_grant","error_description":"Code expired"}';
      Exit;
    end;

    // Verify PKCE: BASE64URL(SHA256(code_verifier)) must equal the stored code_challenge
    ComputedChallenge := Base64URLEncode(THashSHA2.GetHashBytes(CodeVerifier));

    if ComputedChallenge <> Entry.CodeChallenge then
    begin
      ResponseInfo.ResponseNo  := HTTP_BAD_REQUEST;
      ResponseInfo.ContentType := 'application/json';
      ResponseInfo.ContentText := '{"error":"invalid_grant","error_description":"PKCE verification failed"}';
      Exit;
    end;

    FAuthCodes.Remove(Code); // one-time use
  finally
    FAuthCodesLock.Leave;
  end;

  TokenJSON := TJSONObject.Create;
  try
    TokenJSON.AddPair('access_token', GenerateJWT);
    TokenJSON.AddPair('token_type',   'bearer');
    TokenJSON.AddPair('expires_in',   TJSONNumber.Create(FSettings.OAuthTokenExpiry));

    ResponseInfo.ContentType := 'application/json';
    ResponseInfo.CustomHeaders.Values['Cache-Control'] := 'no-store';
    ResponseInfo.ContentText := TokenJSON.ToJSON;
    ResponseInfo.ResponseNo  := HTTP_OK;
    TLogger.Info('OAuth: issued access token');
  finally
    TokenJSON.Free;
  end;
end;

end.
