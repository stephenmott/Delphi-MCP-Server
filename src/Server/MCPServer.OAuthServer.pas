unit MCPServer.OAuthServer;

// Built-in OAuth 2.0 authorization server (stephenmott fork; not in GDK upstream).
//
// Upstream ships the resource-server half of OAuth (IMCPAuthorizer, the 401
// challenge, protected-resource metadata from [Auth] settings) but no
// authorization server. This unit is one: dynamic client registration, a
// password form at /authorize, PKCE (S256), HS256 JWT access tokens and rotating
// refresh tokens persisted beside the settings file.
//
// It is wired into TMCPIdHTTPServer when [OAuth] Enabled=1 and takes over from
// upstream's IMCPAuthorizer path for the MCP endpoint. Every URL it advertises
// is derived from the request (Host + X-Forwarded-Proto), so a server behind a
// reverse proxy needs no [Auth] ResourceUri/AuthorizationServers settings.
//
// The bearer token is read from X-MCP-Authorization first, then Authorization:
// the nginx front end renames the header so that Indy's own authentication
// handling never sees it.

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  IdCustomHTTPServer,
  MCPServer.Settings;

type
  TMCPOAuthServer = class
  private type
    TAuthCodeEntry = record
      CodeChallenge: string;
      RedirectURI: string;
      State: string;
      ExpiresAt: TDateTime;
    end;

    TRefreshTokenEntry = record
      IssuedAt: TDateTime;
      ExpiresAt: TDateTime;
    end;
  private
    FSettings: TMCPSettings;
    FAuthCodes: TDictionary<string, TAuthCodeEntry>;
    FAuthCodesLock: TCriticalSection;
    FRefreshTokens: TDictionary<string, TRefreshTokenEntry>;
    FRefreshTokensLock: TCriticalSection;
    function Base64URLEncode(const Bytes: TBytes): string;
    function Base64URLDecode(const S: string): TBytes;
    function ParseFormParams(const Body: string): TDictionary<string, string>;
    function ReadBody(RequestInfo: TIdHTTPRequestInfo): string;
    function GenerateAuthCode: string;
    procedure CleanExpiredAuthCodes;
    function GenerateRefreshToken: string;
    procedure CleanExpiredRefreshTokens;
    function GetRefreshTokensFilePath: string;
    procedure IssueTokens(ResponseInfo: TIdHTTPResponseInfo; const LogMessage: string);
    function GenerateJWT: string;
    function HTMLEncode(const S: string): string;
    function GetParam(Params: TDictionary<string, string>; const Key: string): string;
    procedure SendJsonText(ResponseInfo: TIdHTTPResponseInfo; Status: Integer; const Json: string);
    procedure HandleWellKnownOAuth(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleProtectedResourceMetadata(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleRegister(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleAuthorize(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
    procedure HandleToken(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo);
  public
    constructor Create(Settings: TMCPSettings);
    destructor Destroy; override;

    procedure LoadRefreshTokens;
    procedure SaveRefreshTokens;

    /// <summary>The public base URL (scheme://host) the client used to reach us.</summary>
    function GetRequestBaseURL(RequestInfo: TIdHTTPRequestInfo): string;

    /// <summary>
    /// Serves the OAuth endpoints and both .well-known documents. Returns False
    /// for any other path, leaving the request to the MCP server.
    /// </summary>
    function TryHandle(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo): Boolean;

    /// <summary>
    /// Checks the bearer token on an MCP endpoint request. On failure writes a
    /// 401 carrying an RFC 9728 resource_metadata challenge and returns False.
    /// </summary>
    function Authenticate(RequestInfo: TIdHTTPRequestInfo; ResponseInfo: TIdHTTPResponseInfo): Boolean;

    function ValidateBearerToken(const Token: string): Boolean;
  end;

implementation

uses
  System.JSON,
  System.IOUtils,
  System.Hash,
  System.DateUtils,
  System.NetEncoding,
  IdGlobal,
  IdURI,
  MCPServer.Logger;

const
  HTTP_OK = 200;
  HTTP_CREATED = 201;
  HTTP_FOUND = 302;
  HTTP_BAD_REQUEST = 400;
  HTTP_UNAUTHORIZED = 401;
  HTTP_METHOD_NOT_ALLOWED = 405;

  // Auth code lifetime: 10 minutes
  AUTH_CODE_LIFETIME = 10 / (24 * 60);

  OAUTH_WELL_KNOWN_PATH    = '/.well-known/oauth-authorization-server';
  OAUTH_PROTECTED_RESOURCE = '/.well-known/oauth-protected-resource';
  OAUTH_AUTHORIZE_PATH     = '/authorize';
  OAUTH_TOKEN_PATH         = '/token';
  OAUTH_REGISTER_PATH      = '/register';

  REFRESH_TOKENS_FILE = 'refresh_tokens.json';

  // Simple HTML login form - %s slots: error_html, client_id, redirect_uri, code_challenge, state
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

{ TMCPOAuthServer }

constructor TMCPOAuthServer.Create(Settings: TMCPSettings);
begin
  inherited Create;
  FSettings := Settings;
  FAuthCodes := TDictionary<string, TAuthCodeEntry>.Create;
  FAuthCodesLock := TCriticalSection.Create;
  FRefreshTokens := TDictionary<string, TRefreshTokenEntry>.Create;
  FRefreshTokensLock := TCriticalSection.Create;
end;

destructor TMCPOAuthServer.Destroy;
begin
  SaveRefreshTokens;
  FRefreshTokens.Free;
  FRefreshTokensLock.Free;
  FAuthCodes.Free;
  FAuthCodesLock.Free;
  inherited;
end;

function TMCPOAuthServer.TryHandle(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo): Boolean;
begin
  Result := True;
  const RequestPath = RequestInfo.Document;

  // Discovery documents and the token/registration endpoints are called
  // cross-origin by browser-based clients.
  if RequestPath = OAUTH_WELL_KNOWN_PATH then
  begin
    ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';
    HandleWellKnownOAuth(RequestInfo, ResponseInfo);
  end
  // RFC 9728: /.well-known/oauth-protected-resource/{resource-path}
  else if RequestPath.StartsWith(OAUTH_PROTECTED_RESOURCE) then
  begin
    ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';
    HandleProtectedResourceMetadata(RequestInfo, ResponseInfo);
  end
  else if RequestPath = OAUTH_AUTHORIZE_PATH then
    HandleAuthorize(RequestInfo, ResponseInfo)
  else if RequestPath = OAUTH_TOKEN_PATH then
    HandleToken(RequestInfo, ResponseInfo)
  else if RequestPath = OAUTH_REGISTER_PATH then
    HandleRegister(RequestInfo, ResponseInfo)
  else
    Result := False;
end;

function TMCPOAuthServer.Authenticate(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo): Boolean;
var
  AuthHeader: string;
  BearerToken: string;
begin
  // X-MCP-Authorization wins (set by nginx); Authorization is the fallback for
  // direct connections that bypass the proxy.
  AuthHeader := Trim(RequestInfo.RawHeaders.Values['X-MCP-Authorization']);
  if AuthHeader = '' then
    AuthHeader := Trim(RequestInfo.RawHeaders.Values['Authorization']);

  if AuthHeader.StartsWith('Bearer ', True) then
    BearerToken := AuthHeader.Substring(7).Trim
  else
    BearerToken := '';

  TLogger.Info(Format('MCP auth: Authorization header length=%d, token length=%d',
    [Length(AuthHeader), Length(BearerToken)]));

  Result := ValidateBearerToken(BearerToken);
  if Result then
    Exit;

  // RFC 9728 / MCP 2025-06-18: the 401 MUST point the client at the
  // protected-resource metadata so it can discover the authorization server.
  // Newer MCP clients (e.g. Claude Desktop) require resource_metadata here and
  // no longer fall back to probing .well-known paths.
  ResponseInfo.ResponseNo := HTTP_UNAUTHORIZED;
  ResponseInfo.ResponseText := 'Unauthorized';
  ResponseInfo.CustomHeaders.Values['WWW-Authenticate'] :=
    Format('Bearer realm="%0:s", resource_metadata="%0:s%1:s%2:s"',
      [GetRequestBaseURL(RequestInfo), OAUTH_PROTECTED_RESOURCE, FSettings.Endpoint]);
  ResponseInfo.ContentType := 'application/json';
  ResponseInfo.ContentText := '{"error":"invalid_token"}';
  TLogger.Warning('Rejected unauthenticated MCP request from: ' + RequestInfo.RemoteIP);
end;

// -- Helpers ------------------------------------------------------------------

function TMCPOAuthServer.Base64URLEncode(const Bytes: TBytes): string;
begin
  Result := TNetEncoding.Base64.EncodeBytesToString(Bytes);
  // Strip the line breaks Delphi's Base64 encoder adds every 76 chars -
  // newlines in a JWT would break Authorization header transmission
  Result := Result.Replace(#13#10, '', [rfReplaceAll])
                  .Replace(#13,    '', [rfReplaceAll])
                  .Replace(#10,    '', [rfReplaceAll])
                  .Replace('+', '-', [rfReplaceAll])
                  .Replace('/', '_', [rfReplaceAll])
                  .Replace('=', '',  [rfReplaceAll]);
end;

function TMCPOAuthServer.Base64URLDecode(const S: string): TBytes;
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

function TMCPOAuthServer.ParseFormParams(const Body: string): TDictionary<string, string>;
var
  Parts: TArray<string>;
begin
  Result := TDictionary<string, string>.Create;
  for var Pair in Body.Split(['&']) do
  begin
    Parts := Pair.Split(['='], 2);
    if Length(Parts) = 2 then
      Result.AddOrSetValue(TIdURI.URLDecode(Parts[0]), TIdURI.URLDecode(Parts[1]));
  end;
end;

function TMCPOAuthServer.ReadBody(RequestInfo: TIdHTTPRequestInfo): string;
begin
  Result := RequestInfo.FormParams;
  if (Result = '') and Assigned(RequestInfo.PostStream) and (RequestInfo.PostStream.Size > 0) then
  begin
    RequestInfo.PostStream.Position := 0;
    Result := ReadStringFromStream(RequestInfo.PostStream, -1, IndyTextEncoding_UTF8);
  end;
end;

function TMCPOAuthServer.GetRequestBaseURL(RequestInfo: TIdHTTPRequestInfo): string;
var
  Proto, Host: string;
begin
  // Honour nginx X-Forwarded-Proto so we advertise the public https:// URL
  Proto := RequestInfo.RawHeaders.Values['X-Forwarded-Proto'];
  if Proto = '' then
  begin
    if FSettings.SSLEnabled then
      Proto := 'https'
    else
      Proto := 'http';
  end;
  Host := RequestInfo.RawHeaders.Values['Host'];
  if Host = '' then
    Host := FSettings.Host + ':' + IntToStr(FSettings.Port);
  Result := Proto + '://' + Host;
end;

function TMCPOAuthServer.GenerateAuthCode: string;
var
  G: TGUID;
begin
  CreateGUID(G);
  Result := GUIDToString(G).Replace('{', '', [rfReplaceAll])
                            .Replace('}', '', [rfReplaceAll])
                            .Replace('-', '', [rfReplaceAll])
                            .ToLower;
end;

procedure TMCPOAuthServer.CleanExpiredAuthCodes;
var
  Expired: TList<string>;
begin
  // Caller must hold FAuthCodesLock
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

function TMCPOAuthServer.GenerateJWT: string;
var
  Header, Payload, SignInput: string;
  NowUnix, ExpUnix: Int64;
  KeyBytes, SigBytes: TBytes;
begin
  NowUnix := DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now));
  ExpUnix := NowUnix + FSettings.OAuthTokenExpiry;

  Header  := '{"alg":"HS256","typ":"JWT"}';
  Payload := Format('{"iat":%d,"exp":%d,"iss":"nxmcp"}', [NowUnix, ExpUnix]);

  const HeaderEnc = Base64URLEncode(TEncoding.UTF8.GetBytes(Header));
  const PayloadEnc = Base64URLEncode(TEncoding.UTF8.GetBytes(Payload));
  SignInput := HeaderEnc + '.' + PayloadEnc;

  KeyBytes := TEncoding.UTF8.GetBytes(FSettings.OAuthTokenSecret);
  SigBytes := THashSHA2.GetHMACAsBytes(TEncoding.UTF8.GetBytes(SignInput), KeyBytes);

  Result := SignInput + '.' + Base64URLEncode(SigBytes);
end;

function TMCPOAuthServer.ValidateBearerToken(const Token: string): Boolean;
var
  Parts: TArray<string>;
  SignInput: string;
  KeyBytes, SigBytes, ExpectedSig: TBytes;
  PayloadJSON: TJSONObject;
  ExpValue: Int64;
begin
  Result := False;

  if FSettings.OAuthTokenSecret = '' then
    Exit;

  Parts := Token.Split(['.']);
  if Length(Parts) <> 3 then
  begin
    TLogger.Warning('ValidateBearerToken: wrong number of parts: ' + IntToStr(Length(Parts)));
    Exit;
  end;

  // Verify HMAC-SHA256 signature
  SignInput   := Parts[0] + '.' + Parts[1];
  KeyBytes    := TEncoding.UTF8.GetBytes(FSettings.OAuthTokenSecret);
  ExpectedSig := THashSHA2.GetHMACAsBytes(TEncoding.UTF8.GetBytes(SignInput), KeyBytes);
  SigBytes    := Base64URLDecode(Parts[2]);

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
  PayloadJSON := TJSONObject.ParseJSONValue(
    TEncoding.UTF8.GetString(Base64URLDecode(Parts[1]))) as TJSONObject;
  if not Assigned(PayloadJSON) then
  begin
    TLogger.Warning('ValidateBearerToken: could not parse payload');
    Exit;
  end;
  try
    const ExpVal = PayloadJSON.GetValue('exp');
    if not Assigned(ExpVal) then
    begin
      TLogger.Warning('ValidateBearerToken: no exp claim');
      Exit;
    end;
    ExpValue := StrToInt64(ExpVal.Value);
    const NowUnix = DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now));
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

function TMCPOAuthServer.GetParam(Params: TDictionary<string, string>; const Key: string): string;
begin
  if not Params.TryGetValue(Key, Result) then
    Result := '';
end;

function TMCPOAuthServer.HTMLEncode(const S: string): string;
begin
  Result := S.Replace('&',  '&amp;',  [rfReplaceAll])
             .Replace('<',  '&lt;',   [rfReplaceAll])
             .Replace('>',  '&gt;',   [rfReplaceAll])
             .Replace('"',  '&quot;', [rfReplaceAll])
             .Replace('''', '&#39;',  [rfReplaceAll]);
end;

procedure TMCPOAuthServer.SendJsonText(ResponseInfo: TIdHTTPResponseInfo; Status: Integer;
  const Json: string);
begin
  ResponseInfo.ResponseNo := Status;
  ResponseInfo.ContentType := 'application/json';
  ResponseInfo.ContentText := Json;
end;

// -- Endpoint handlers --------------------------------------------------------

procedure TMCPOAuthServer.HandleWellKnownOAuth(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
begin
  const Base = GetRequestBaseURL(RequestInfo);
  const Meta = TJSONObject.Create;
  try
    Meta.AddPair('issuer',                 Base);
    Meta.AddPair('authorization_endpoint', Base + OAUTH_AUTHORIZE_PATH);
    Meta.AddPair('token_endpoint',         Base + OAUTH_TOKEN_PATH);

    const RespTypes = TJSONArray.Create;
    RespTypes.Add('code');
    Meta.AddPair('response_types_supported', RespTypes);

    const GrantTypes = TJSONArray.Create;
    GrantTypes.Add('authorization_code');
    GrantTypes.Add('refresh_token');
    Meta.AddPair('grant_types_supported', GrantTypes);

    const ChallengeMethods = TJSONArray.Create;
    ChallengeMethods.Add('S256');
    Meta.AddPair('code_challenge_methods_supported', ChallengeMethods);

    const AuthMethods = TJSONArray.Create;
    AuthMethods.Add('none');
    Meta.AddPair('token_endpoint_auth_methods_supported', AuthMethods);
    Meta.AddPair('registration_endpoint', Base + OAUTH_REGISTER_PATH);

    SendJsonText(ResponseInfo, HTTP_OK, Meta.ToJSON);
  finally
    Meta.Free;
  end;
end;

procedure TMCPOAuthServer.HandleProtectedResourceMetadata(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
begin
  const Base = GetRequestBaseURL(RequestInfo);
  const Meta = TJSONObject.Create;
  try
    Meta.AddPair('resource', Base + FSettings.Endpoint);
    const AuthServers = TJSONArray.Create;
    AuthServers.Add(Base);
    Meta.AddPair('authorization_servers', AuthServers);
    const BearerMethods = TJSONArray.Create;
    BearerMethods.Add('header');
    Meta.AddPair('bearer_methods_supported', BearerMethods);

    SendJsonText(ResponseInfo, HTTP_OK, Meta.ToJSON);
  finally
    Meta.Free;
  end;
end;

procedure TMCPOAuthServer.HandleRegister(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
begin
  // RFC 7591 dynamic client registration - accept any client, return a client_id.
  // Real auth is the password form at /authorize, not client credentials.
  ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';

  if RequestInfo.CommandType <> hcPOST then
  begin
    ResponseInfo.ResponseNo := HTTP_METHOD_NOT_ALLOWED;
    Exit;
  end;

  const Body = ReadBody(RequestInfo);
  const ClientID = GenerateAuthCode; // GUID generator doubles as a unique client_id

  const ResponseJSON = TJSONObject.Create;
  try
    ResponseJSON.AddPair('client_id', ClientID);
    ResponseJSON.AddPair('client_id_issued_at', TJSONNumber.Create(
      DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now))));
    ResponseJSON.AddPair('token_endpoint_auth_method', 'none');

    // Echo back redirect_uris and grant_types from the request if present
    const RequestJSON = TJSONObject.ParseJSONValue(Body);
    try
      if RequestJSON is TJSONObject then
      begin
        const RedirectURIs = TJSONObject(RequestJSON).GetValue('redirect_uris');
        if Assigned(RedirectURIs) then
          ResponseJSON.AddPair('redirect_uris', RedirectURIs.Clone as TJSONValue);
        const GrantTypes = TJSONObject(RequestJSON).GetValue('grant_types');
        if Assigned(GrantTypes) then
          ResponseJSON.AddPair('grant_types', GrantTypes.Clone as TJSONValue);
      end;
    finally
      RequestJSON.Free;
    end;

    ResponseInfo.ResponseText := 'Created';
    ResponseInfo.CustomHeaders.Values['Cache-Control'] := 'no-store';
    SendJsonText(ResponseInfo, HTTP_CREATED, ResponseJSON.ToJSON);
    TLogger.Info('OAuth: registered client_id=' + ClientID);
  finally
    ResponseJSON.Free;
  end;
end;

procedure TMCPOAuthServer.HandleAuthorize(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
var
  Params: TDictionary<string, string>;
  ClientID, RedirectURI, CodeChallenge, State, Password: string;
  Entry: TAuthCodeEntry;
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
    const Body = ReadBody(RequestInfo);
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

    const AuthCode = GenerateAuthCode;
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

    var Location := RedirectURI + '?code=' + AuthCode;
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

procedure TMCPOAuthServer.IssueTokens(ResponseInfo: TIdHTTPResponseInfo; const LogMessage: string);
var
  RefreshEntry: TRefreshTokenEntry;
begin
  const NewRefreshToken = GenerateRefreshToken;
  RefreshEntry.IssuedAt  := Now;
  RefreshEntry.ExpiresAt := Now + FSettings.OAuthRefreshTokenExpiry * (1.0 / 86400.0);

  FRefreshTokensLock.Enter;
  try
    CleanExpiredRefreshTokens;
    FRefreshTokens.AddOrSetValue(NewRefreshToken, RefreshEntry);
  finally
    FRefreshTokensLock.Leave;
  end;
  SaveRefreshTokens;

  const TokenJSON = TJSONObject.Create;
  try
    TokenJSON.AddPair('access_token',  GenerateJWT);
    TokenJSON.AddPair('token_type',    'bearer');
    TokenJSON.AddPair('expires_in',    TJSONNumber.Create(FSettings.OAuthTokenExpiry));
    TokenJSON.AddPair('refresh_token', NewRefreshToken);

    ResponseInfo.CustomHeaders.Values['Cache-Control'] := 'no-store';
    SendJsonText(ResponseInfo, HTTP_OK, TokenJSON.ToJSON);
    TLogger.Info(LogMessage);
  finally
    TokenJSON.Free;
  end;
end;

procedure TMCPOAuthServer.HandleToken(RequestInfo: TIdHTTPRequestInfo;
  ResponseInfo: TIdHTTPResponseInfo);
var
  Params: TDictionary<string, string>;
  Code, CodeVerifier, GrantType, OldRefreshToken: string;
  AuthEntry: TAuthCodeEntry;
  RefreshEntry: TRefreshTokenEntry;
begin
  // Token endpoint always allows any origin so clients can call it cross-origin
  ResponseInfo.CustomHeaders.Values['Access-Control-Allow-Origin'] := '*';

  if RequestInfo.CommandType <> hcPOST then
  begin
    ResponseInfo.ResponseNo := HTTP_METHOD_NOT_ALLOWED;
    Exit;
  end;

  Params := ParseFormParams(ReadBody(RequestInfo));
  try
    GrantType       := GetParam(Params, 'grant_type');
    Code            := GetParam(Params, 'code');
    CodeVerifier    := GetParam(Params, 'code_verifier');
    OldRefreshToken := GetParam(Params, 'refresh_token');
  finally
    Params.Free;
  end;

  TLogger.Info(Format('OAuth /token request: grant_type=%s, code len=%d, verifier len=%d, refresh_token len=%d',
    [GrantType, Length(Code), Length(CodeVerifier), Length(OldRefreshToken)]));

  if GrantType = 'authorization_code' then
  begin
    FAuthCodesLock.Enter;
    try
      if not FAuthCodes.TryGetValue(Code, AuthEntry) then
      begin
        TLogger.Warning('OAuth /token: REJECTED - auth code not found in store ' +
          Format('(received code len=%d, %d code(s) currently stored)', [Length(Code), FAuthCodes.Count]));
        SendJsonText(ResponseInfo, HTTP_BAD_REQUEST, '{"error":"invalid_grant"}');
        Exit;
      end;

      if Now > AuthEntry.ExpiresAt then
      begin
        TLogger.Warning('OAuth /token: REJECTED - auth code expired');
        FAuthCodes.Remove(Code);
        SendJsonText(ResponseInfo, HTTP_BAD_REQUEST,
          '{"error":"invalid_grant","error_description":"Code expired"}');
        Exit;
      end;

      // PKCE: BASE64URL(SHA256(code_verifier)) must equal the stored code_challenge
      const ComputedChallenge = Base64URLEncode(THashSHA2.GetHashBytes(CodeVerifier));
      if ComputedChallenge <> AuthEntry.CodeChallenge then
      begin
        TLogger.Warning(Format('OAuth /token: REJECTED - PKCE mismatch (computed=%s expected=%s)',
          [ComputedChallenge, AuthEntry.CodeChallenge]));
        SendJsonText(ResponseInfo, HTTP_BAD_REQUEST,
          '{"error":"invalid_grant","error_description":"PKCE verification failed"}');
        Exit;
      end;

      FAuthCodes.Remove(Code); // one-time use
    finally
      FAuthCodesLock.Leave;
    end;

    IssueTokens(ResponseInfo, 'OAuth: issued access token and refresh token');
  end
  else if GrantType = 'refresh_token' then
  begin
    // Consume the incoming refresh token immediately (rotation)
    var RefreshFound := False;
    FRefreshTokensLock.Enter;
    try
      if FRefreshTokens.TryGetValue(OldRefreshToken, RefreshEntry) then
      begin
        FRefreshTokens.Remove(OldRefreshToken); // consume regardless - rotation or expired
        RefreshFound := Now <= RefreshEntry.ExpiresAt;
      end;
    finally
      FRefreshTokensLock.Leave;
    end;

    if not RefreshFound then
    begin
      SendJsonText(ResponseInfo, HTTP_BAD_REQUEST,
        '{"error":"invalid_grant","error_description":"Invalid or expired refresh token"}');
      TLogger.Warning('OAuth: rejected invalid/expired refresh token from: ' + RequestInfo.RemoteIP);
      Exit;
    end;

    IssueTokens(ResponseInfo, 'OAuth: refreshed access token (rotated refresh token)');
  end
  else
  begin
    TLogger.Warning('OAuth /token: REJECTED - unsupported grant_type "' + GrantType + '"');
    SendJsonText(ResponseInfo, HTTP_BAD_REQUEST, '{"error":"unsupported_grant_type"}');
  end;
end;

// -- Refresh token persistence ------------------------------------------------

function TMCPOAuthServer.GenerateRefreshToken: string;
var
  G1, G2: TGUID;
begin
  // Two GUIDs concatenated = 256 bits of randomness
  CreateGUID(G1);
  CreateGUID(G2);
  Result := (GUIDToString(G1) + GUIDToString(G2))
    .Replace('{', '', [rfReplaceAll])
    .Replace('}', '', [rfReplaceAll])
    .Replace('-', '', [rfReplaceAll])
    .ToLower;
end;

procedure TMCPOAuthServer.CleanExpiredRefreshTokens;
var
  Expired: TList<string>;
begin
  // Caller must hold FRefreshTokensLock
  Expired := TList<string>.Create;
  try
    for var Pair in FRefreshTokens do
      if Now > Pair.Value.ExpiresAt then
        Expired.Add(Pair.Key);
    for var Key in Expired do
      FRefreshTokens.Remove(Key);
  finally
    Expired.Free;
  end;
end;

function TMCPOAuthServer.GetRefreshTokensFilePath: string;
begin
  Result := TPath.Combine(TPath.GetDirectoryName(FSettings.SettingsFile), REFRESH_TOKENS_FILE);
end;

procedure TMCPOAuthServer.SaveRefreshTokens;
var
  Wrapper: TJSONObject;
  TokensArr: TJSONArray;
  TokenEntry: TJSONObject;
begin
  Wrapper   := TJSONObject.Create;
  TokensArr := TJSONArray.Create;
  try
    Wrapper.AddPair('refresh_tokens', TokensArr); // Wrapper takes ownership

    FRefreshTokensLock.Enter;
    try
      CleanExpiredRefreshTokens;
      for var Pair in FRefreshTokens do
      begin
        TokenEntry := TJSONObject.Create;
        TokenEntry.AddPair('token',      Pair.Key);
        TokenEntry.AddPair('issued_at',  TJSONNumber.Create(
          DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Pair.Value.IssuedAt))));
        TokenEntry.AddPair('expires_at', TJSONNumber.Create(
          DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Pair.Value.ExpiresAt))));
        TokensArr.AddElement(TokenEntry);
      end;
    finally
      FRefreshTokensLock.Leave;
    end;

    TFile.WriteAllText(GetRefreshTokensFilePath, Wrapper.ToJSON, TEncoding.UTF8);
    TLogger.Info(Format('OAuth: saved %d refresh token(s)', [TokensArr.Count]));
  finally
    Wrapper.Free; // also frees TokensArr and all entries
  end;
end;

procedure TMCPOAuthServer.LoadRefreshTokens;
var
  Root: TJSONObject;
  TokensArr: TJSONArray;
  Item: TJSONObject;
  Entry: TRefreshTokenEntry;
  TokenVal, IssuedVal, ExpiresVal: TJSONValue;
  Loaded: Integer;
begin
  const FilePath = GetRefreshTokensFilePath;
  if not TFile.Exists(FilePath) then
    Exit;

  try
    Root := TJSONObject.ParseJSONValue(TFile.ReadAllText(FilePath, TEncoding.UTF8)) as TJSONObject;
    if not Assigned(Root) then
      Exit;
    try
      TokensArr := Root.GetValue('refresh_tokens') as TJSONArray;
      if not Assigned(TokensArr) then
        Exit;

      Loaded := 0;
      FRefreshTokensLock.Enter;
      try
        for var I := 0 to TokensArr.Count - 1 do
        begin
          Item := TokensArr.Items[I] as TJSONObject;
          if not Assigned(Item) then
            Continue;

          TokenVal   := Item.GetValue('token');
          IssuedVal  := Item.GetValue('issued_at');
          ExpiresVal := Item.GetValue('expires_at');
          if not Assigned(TokenVal) or not Assigned(IssuedVal) or not Assigned(ExpiresVal) then
            Continue;

          Entry.IssuedAt  := TTimeZone.Local.ToLocalTime(UnixToDateTime(StrToInt64(IssuedVal.Value)));
          Entry.ExpiresAt := TTimeZone.Local.ToLocalTime(UnixToDateTime(StrToInt64(ExpiresVal.Value)));

          if Now < Entry.ExpiresAt then
          begin
            FRefreshTokens.AddOrSetValue(TokenVal.Value, Entry);
            Inc(Loaded);
          end;
        end;
      finally
        FRefreshTokensLock.Leave;
      end;

      TLogger.Info(Format('OAuth: loaded %d refresh token(s) from %s', [Loaded, FilePath]));
    finally
      Root.Free;
    end;
  except
    on E: Exception do
      TLogger.Warning('OAuth: failed to load refresh tokens: ' + E.Message);
  end;
end;

end.
