# 1. 简介 - Introduction

在传统的客户端-服务端认证模式中，客户端需要使用资源所有者（如：最终用户）的凭证（如：用户名密码）与服务端进行认证，以请求服务端上的访问受限的资源（受保护资源）。为了向第三方应用提供对受限资源的访问权限，资源所有者需要将自己的凭证共享给第三方。这就产生了几个问题和局限：

* 为保证长期可用，第三方应用必须保存资源所有者的凭证，比如明文密码。
* 服务端需要支持密码验证，尽管该方式存在固有的安全风险。
* 第三方应用对资源所有者的受保护资源的访问权限过于宽泛，使得资源所有者没有能力限制其访问期限，或者限制其访问受限资源的子集。
* 资源所有者在撤销对某个第三方应用的访问权限时，也势必会撤销对所有第三方应用的访问权限，因为只能采取修改密码的方式来实现撤销。
* 任何第三方应用程序的泄露问题，都会导致最终用户的密码以及所有受改密码保护的数据的泄露。

> In the traditional client-server authentication model, the client
>    requests an access-restricted resource (protected resource) on the
>    server by authenticating with the server using the resource owner's
>    credentials.  In order to provide third-party applications access to
>    restricted resources, the resource owner shares its credentials with
>    the third party.  This creates several problems and limitations:
>
>  o  Third-party applications are required to store the resource
>     owner's credentials for future use, typically a password in
>     clear-text.
>
>  o  Servers are required to support password authentication, despite
>     the security weaknesses inherent in passwords.
>
>  o  Third-party applications gain overly broad access to the resource
>      owner's protected resources, leaving resource owners without any
>      ability to restrict duration or access to a limited subset of
>      resources.
>
>   o  Resource owners cannot revoke access to an individual third party
>      without revoking access to all third parties, and must do so by
>      changing the third party's password.
>
>   o  Compromise of any third-party application results in compromise of
>      the end-user's password and all of the data protected by that
>      password.

OAuth通过提供授权层，以及将客户端和资源所有者的角色分开的方式来解决这些问题。在OAuth中，客户端请求访问的资源，由资源所有者控制并由资源服务器托管，并且会获得一套与资源所有者不同的凭证。

> OAuth addresses these issues by introducing an authorization layer
>   and separating the role of the client from that of the resource
>   owner.  In OAuth, the client requests access to resources controlled
>   by the resource owner and hosted by the resource server, and is
>   issued a different set of credentials than those of the resource
>   owner.

为替代使用资源所有者凭证来访问受保护资源的方式，客户端改为获取一个access token -- 一个标识特定范围、寿命和其它访问属性的字符串。访问令牌由授权服务器经资源所有者批准后签发给第三方客户端，客户端通过携带access token来访问被资源服务器托管的受保护资源。

> Instead of using the resource owner's credentials to access protected
>    resources, the client obtains an access token -- a string denoting a
>    specific scope, lifetime, and other access attributes.  Access tokens
>    are issued to third-party clients by an authorization server with the
>    approval of the resource owner.  The client uses the access token to
>    access the protected resources hosted by the resource server.

例如，最终用户（资源所有者）允许打印服务（客户端）访问他存储在照片共享服务（资源服务器）的受保护的照片，而无需与打印服务共享他的用户名和密码。相反，他直接与照片共享服务信任的服务器（授权服务器）进行认证，该服务器向打印服务发放特定的凭证（访问令牌）。

> For example, an end-user (resource owner) can grant a printing
>    service (client) access to her protected photos stored at a photo-
>    sharing service (resource server), without sharing her username and
>    password with the printing service.  Instead, she authenticates
>    directly with a server trusted by the photo-sharing service
>    (authorization server), which issues the printing service delegation-
>    specific credentials (access token).

本规范是为HTTP设计的([RFC2616])，在HTTP以外的任何协议上使用OAuth都不在本规范的约定范围内。

> This specification is designed for use with HTTP ([RFC2616]).  The
>    use of OAuth over any protocol other than HTTP is out of scope.

OAuth 1.0([RFC5849])协议，是一个小规模的临时社区的成果，最终以资料的形式发布。本标准跟踪（一份RFC规范说明想要提升到正式标准的程度，需要通过“成熟度等级”来评估，该过程称为Standards Track）规范建立在OAuth 1.0部署经验的基础上，同时也从更广泛的IETF社区搜集到额外的用例和可扩展性需求。OAuth 2.0协议不会向后兼容OAuth 1.0，这两种版本的协议可以在网上共存，也都提供支持。然而，本文档的目的是让新的实现按照本文档的规范来支持OAuth 2.0，0Auth 1.0仅用于支持现有的部署。OAuth 2.0与OAuth 1.0协议之间能共享的实践细节很少，所以熟悉OAuth 1.0的实施人员不应该按OAuth 1.0的情况来假设本文档的结构和细节。

> The OAuth 1.0 protocol ([RFC5849]), published as an informational
>    document, was the result of a small ad hoc community effort.  This
>    Standards Track specification builds on the OAuth 1.0 deployment
>    experience, as well as additional use cases and extensibility
>    requirements gathered from the wider IETF community.  The OAuth 2.0
>    protocol is not backward compatible with OAuth 1.0.  The two versions
>    may co-exist on the network, and implementations may choose to
>    support both.  However, it is the intention of this specification
>    that new implementations support OAuth 2.0 as specified in this
>    document and that OAuth 1.0 is used only to support existing
>    deployments.  The OAuth 2.0 protocol shares very few implementation
>    details with the OAuth 1.0 protocol.  Implementers familiar with
>    OAuth 1.0 should approach this document without any assumptions as to
>    its structure and details.

## 1.1 角色 - Roles

OAuth定义四种角色：

    资源所有者
        能够授权访问受保护资源的实体，如果资源所有者是个人，则称为最终用户。

    资源服务器
        托管受保护资源的服务器，能够接收并响应携带access token访问受保护资源的请求。

    客户端
        作为资源所有者的“代理”，在其授权下访问受保护资源的应用程序。其中“client（即客户端）”一词并不意味着任何特定的实施特征（如，该应用是在服务器、桌面或其它设备上运行）。

    授权服务器
        在成功认证资源所有者并获得授权后，向客户端签发access token的服务器。

> OAuth defines four roles:
>
>     resource owner
>         An entity capable of granting access to a protected resource.
>         When the resource owner is a person, it is referred to as an end-user.
>
>     resource server
>         The server hosting the protected resources, capable of accepting
>         and responding to protected resource requests using access tokens.
>
>     client
>         An application making protected resource requests on behalf of the
>         resource owner and with its authorization.  The term "client" does
>         not imply any particular implementation characteristics (e.g.,
>         whether the application executes on a server, a desktop, or other
>         devices).
>
>     authorization server
>         The server issuing access tokens to the client after successfully
>         authenticating the resource owner and obtaining authorization.

授权服务器和资源服务器之间的交互超出了本规范的描述范围。授权服务器可以与资源服务器是同一台服务器，也可以是一台单独的机器。一台授权服务器签发的令牌可能供多台资源服务器使用。

> The interaction between the authorization server and resource server
>    is beyond the scope of this specification.  The authorization server
>    may be the same server as the resource server or a separate entity.
>    A single authorization server may issue access tokens accepted by
>    multiple resource servers.

## 1.2 协议流程 - Protocol Flow

     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+

图一所示的OAuth 2.0的抽象流程描述了四个角色之间的交互，包括以下步骤：

* (A) 客户端向资源所有者请求授予权限。授权请求可以由客户端直接向资源所有者发起（如图所示），或者更好的方式是由授权服务器作为中间人间接发起。

* (B) 客户端接收到的授权许可，是代表资源所有者的授权凭证（如：Authorization Code），通常采用本规范中定义的四种授权类型或其它扩展类型来获取。

* (C) 客户端通过与授权服务器发起身份认证以及出式授权许可，来换取access token。

* (D) 授权服务器对客户端进行身份认证，并验证授权许可，如果验证通过，则签发access token。

* (E) 客户端从资源服务器中请求访问受保护的资源，并通过出示access token来获取认证。

* (F) 资源服务器校验access token，如果验证通过，则处理该请求。

> The abstract OAuth 2.0 flow illustrated in Figure 1 describes the
>    interaction between the four roles and includes the following steps:
>
>    (A)  The client requests authorization from the resource owner.  The
>         authorization request can be made directly to the resource owner
>         (as shown), or preferably indirectly via the authorization
>         server as an intermediary.
>
>    (B)  The client receives an authorization grant, which is a
>         credential representing the resource owner's authorization,
>         expressed using one of four grant types defined in this
>         specification or using an extension grant type.  The
>         authorization grant type depends on the method used by the
>         client to request authorization and the types supported by the
>         authorization server.
>
>    (C)  The client requests an access token by authenticating with the
>         authorization server and presenting the authorization grant.
>
>    (D)  The authorization server authenticates the client and validates
>         the authorization grant, and if valid, issues an access token.
>
>    (E)  The client requests the protected resource from the resource
>         server and authenticates by presenting the access token.
>
>    (F)  The resource server validates the access token, and if valid,
>         serves the request.

客户端从资源所有者处获取授权许可的更好的方式（如步骤A和B中的描述），是使用授权服务器作为中间人，这会在4.1章节的图3中说明。

> The preferred method for the client to obtain an authorization grant
>    from the resource owner (depicted in steps (A) and (B)) is to use the
>    authorization server as an intermediary, which is illustrated in
>    Figure 3 in Section 4.1.

## 1.3 授权许可 - Authorization Grant

授权许可是资源所有者授权的凭证（授权访问其受保护的资源）。本规范定义了四种授权类型：
* authorization code
* implicit
* resource owner password credentials
* client credentials

以及定义其它类型的可扩展的机制。

> An authorization grant is a credential representing > > the resource
>     owner's authorization (to access its protected resources) used by the
>     client to obtain an access token.  This specification defines four
>     grant types -- authorization code, implicit, resource owner password
>     credentials, and client credentials -- as well as an extensibility
>     mechanism for defining additional types.

### 1.3.1 授权码模式 - Authorization Code

授权码的获取，是通过使用授权服务器来作为客户端和资源所有者的中间人。不同于客户端直接向资源拥有者请求授权的模式，授权码模式会将资源拥有者引导到授权服务器（通过[RFC2616]中定义的user-agent），而授权服务器又在生成授权码后，引导资源所有者回到客户端。

> The authorization code is obtained by using an authorization server
>    as an intermediary between the client and resource owner.  Instead of
>    requesting authorization directly from the resource owner, the client
>    directs the resource owner to an authorization server (via its
>    user-agent as defined in [RFC2616]), which in turn directs the
>    resource owner back to the client with the authorization code.

在携带授权码并引导资源所有者返回客户端之前，授权服务器将对资源所有者进行认证，并获取其授权。因为资源所有者只会通过授权服务器进行认证，所以客户端永远无法获得资源所有者的凭证。

> Before directing the resource owner back to the client with the
>    authorization code, the authorization server authenticates the
>    resource owner and obtains authorization.  Because the resource owner
>    only authenticates with the authorization server, the resource
>    owner's credentials are never shared with the client.

授权码提供了一些重要的安全优势，比如能够对客户端进行认证，同时可以直接将access token传输给客户端，无需通过用户的代理，也无需暴露给其他人，包括资源所有者自己。

> The authorization code provides a few important security benefits,
>    such as the ability to authenticate the client, as well as the
>    transmission of the access token directly to the client without
>    passing it through the resource owner's user-agent and potentially
>    exposing it to others, including the resource owner.

### 1.3.2 隐式授权模式 - Implicit

隐式授权模式是简化的授权码模式，它是为基于脚本语言（如Javascript）实现的客户端提供的。在隐式授权模式中，客户端不会获取到授权码，而是直接获取access token（作为资源所有者授权的结果）。该授权类型之所以称为隐式授权模式，是因为没有签发中间凭证（如用于获取access token的授权码）。

> The implicit grant is a simplified authorization code flow optimized
>    for clients implemented in a browser using a scripting language such
>    as JavaScript.  In the implicit flow, instead of issuing the client
>    an authorization code, the client is issued an access token directly
>    (as the result of the resource owner authorization).  The grant type
>    is implicit, as no intermediate credentials (such as an authorization
>    code) are issued (and later used to obtain an access token).

在隐式授权模式中签发access token时，授权服务器不会对客户端进行认证。在某些情况下，客户端的身份可以通过将access token下发给客户端的重定向URI来验证（译者注：比较不严谨的验证方式）。访问零盘可能会暴露给资源所有者，或其它可以访问资源所有者代理的应用程序。

> When issuing an access token during the implicit grant flow, the
>    authorization server does not authenticate the client.  In some
>    cases, the client identity can be verified via the redirection URI
>    used to deliver the access token to the client.  The access token may
>    be exposed to the resource owner or other applications with access to
>    the resource owner's user-agent.

隐式授权模式提高了某些客户端的响应能力和效率（如构建在浏览器上的客户端），因为它减少了获取access token所需的通讯往返次数。然而，这种便利性与使用隐式授权模式带来的安全问题需要进行权衡，例如10.3和10.16章节中描述的，特别是当授权码模式可用时。

> Implicit grants improve the responsiveness and efficiency of some
>    clients (such as a client implemented as an in-browser application),
>    since it reduces the number of round trips required to obtain an
>    access token.  However, this convenience should be weighed against
>    the security implications of using implicit grants, such as those
>    described in Sections 10.3 and 10.16, especially when the
>    authorization code grant type is available.

### 1.3.3 密码凭证模式 - Resource Owner Password Credentials

资源所有者的密码凭证（即用户名密码）可以直接用来获取访问令牌。此种模式只有当资源所有者与客户端之间存在高度信任（例如客户端时设备操作系统的一部分，或是高特权应用），并且其它授权模式（如授权码模式）不可用时才使用。

> The resource owner password credentials (i.e., username and password)
>    can be used directly as an authorization grant to obtain an access
>    token.  The credentials should only be used when there is a high
>    degree of trust between the resource owner and the client (e.g., the
>    client is part of the device operating system or a highly privileged
>    application), and when other authorization grant types are not
>    available (such as an authorization code).

尽管这种授权模式要求客户端直接访问资源所有者的凭证，但资源所有者的凭证仅用于单次请求换取access token。该授权模式可以使客户端无需因将来的使用而存储资源所有者凭证，而是用长效的access token或refresh token来交换令牌。

> Even though this grant type requires direct client access to the
>    resource owner credentials, the resource owner credentials are used
>    for a single request and are exchanged for an access token.  This
>    grant type can eliminate the need for the client to store the
>    resource owner credentials for future use, by exchanging the
>    credentials with a long-lived access token or refresh token.

### 1.3.4 客户端模式 - Client Credentials

当授权请求的范围在客户端的受限访问范围内时，客户端凭证（或其他形式的客户端认证）也可以作为一种授权模式。以客户端凭证作为授权时，客户端通常是代表自己（客户端也是资源所有者）。

> The client credentials (or other forms of client authentication) can
>    be used as an authorization grant when the authorization scope is
>    limited to the protected resources under the control of the client,
>    or to protected resources previously arranged with the authorization
>    server.  Client credentials are used as an authorization grant
>    typically when the client is acting on its own behalf (the client is
>    also the resource owner) or is requesting access to protected
>    resources based on an authorization previously arranged with the
>    authorization server.

## 1.4 访问令牌 - Access Token

访问令牌是用于访问受保护资源的凭证，访问令牌是一个代表资源所有者向客户端签发的凭证的字符串，该字符串对客户端来说通常是不透明的。令牌代表由资源所有者授予的对资源的特定访问范围和时限，并由资源服务器和授权服务器配合强制执行这些控制。

> Access tokens are credentials used to access protected resources.  An
>    access token is a string representing an authorization issued to the
>    client.  The string is usually opaque to the client.  Tokens
>    represent specific scopes and durations of access, granted by the
>    resource owner, and enforced by the resource server and authorization
>    server.

令牌可以是用来获取授权信息的标识符，也可以是以可校验的方式签发的自包含授权信息的令牌（即由一些数据和签名组成的字符串）。客户端使用令牌可能需要额外的凭证，这些凭证不在本规范的范围内，因此不做讨论。

> The token may denote an identifier used to retrieve the authorization
>    information or may self-contain the authorization information in a
>    verifiable manner (i.e., a token string consisting of some data and a
>    signature).  Additional authentication credentials, which are beyond
>    the scope of this specification, may be required in order for the
>    client to use a token.

访问令牌提供了一个抽象层，用一个资源服务器能理解的单一的令牌取代了不同的授权结构（如用户名密码）。通过这种抽象，可以使用比授权模式要求更严格的认证方式来获取访问令牌，并且资源服务器不需要理解这么多种类的认证方法。

> The access token provides an abstraction layer, replacing different
>    authorization constructs (e.g., username and password) with a single
>    token understood by the resource server.  This abstraction enables
>    issuing access tokens more restrictive than the authorization grant
>    used to obtain them, as well as removing the resource server's need
>    to understand a wide range of authentication methods.

根据资源服务器的安全需求，访问令牌可以有不同的格式、结构和使用方法（如加密属性）。访问令牌的属性和用于访问受保护资源的方法不再本规范的讨论范围内，而是由[RFC6750]等配套规范定义。

> Access tokens can have different formats, structures, and methods of
>    utilization (e.g., cryptographic properties) based on the resource
>    server security requirements.  Access token attributes and the
>    methods used to access protected resources are beyond the scope of
>    this specification and are defined by companion specifications such
>    as [RFC6750].

## 1.5 刷新令牌 - Refresh Token

刷新令牌是用来获取访问令牌的凭证。刷新令牌是由授权服务器颁发给客户端的，当当前的访问令牌无效或过期时，可以用来换取新的访问令牌，此外，也可以用作获取范围相同或较窄的额外的访问令牌（访问令牌可能有更短的寿命，而且权限范围也比资源所有者授予的小）。是否签发刷新令牌是可选的，如果授权服务器选择签发刷新令牌，则刷新令牌是同访问令牌一起下发的（即图1的步骤D）。

> Refresh tokens are credentials used to obtain access tokens.  Refresh
>    tokens are issued to the client by the authorization server and are
>    used to obtain a new access token when the current access token
>    becomes invalid or expires, or to obtain additional access tokens
>    with identical or narrower scope (access tokens may have a shorter
>    lifetime and fewer permissions than authorized by the resource
>    owner).  Issuing a refresh token is optional at the discretion of the
>    authorization server.  If the authorization server issues a refresh
>    token, it is included when issuing an access token (i.e., step (D) in
>    Figure 1).

刷新令牌是代表资源所有者授予客户端凭证的字符串，该字符串对客户端通常是不透明的。令牌是用于获取授权信息的标识符，与访问令牌不同，刷新令牌只用于授权服务器，从不发送给资源服务器。

> A refresh token is a string representing the authorization granted to
>    the client by the resource owner.  The string is usually opaque to
>    the client.  The token denotes an identifier used to retrieve the
>    authorization information.  Unlike access tokens, refresh tokens are
>    intended for use only with authorization servers and are never sent
>    to resource servers.

    +--------+                                           +---------------+
    |        |--(A)------- Authorization Grant --------->|               |
    |        |                                           |               |
    |        |<-(B)----------- Access Token -------------|               |
    |        |               & Refresh Token             |               |
    |        |                                           |               |
    |        |                            +----------+   |               |
    |        |--(C)---- Access Token ---->|          |   |               |
    |        |                            |          |   |               |
    |        |<-(D)- Protected Resource --| Resource |   | Authorization |
    | Client |                            |  Server  |   |     Server    |
    |        |--(E)---- Access Token ---->|          |   |               |
    |        |                            |          |   |               |
    |        |<-(F)- Invalid Token Error -|          |   |               |
    |        |                            +----------+   |               |
    |        |                                           |               |
    |        |--(G)----------- Refresh Token ----------->|               |
    |        |                                           |               |
    |        |<-(H)----------- Access Token -------------|               |
    +--------+           & Optional Refresh Token        +---------------+


图2所示的流程包括以下步骤：

* (A) 客户端通过授权服务器进行身份验证，并提出授权许可，申请访问令牌。

* (B) 授权服务器对客户端和授权许可进行验证，如果有效，则签发访问令牌和刷新令牌。

* (C) 客户端通过向资源服务器出示访问令牌来访问受保护的资源。

* (D) 资源服务器验证访问令牌，如果有效，则处理该请求。

* (E) 重复步骤C和D，直到访问令牌过期，如果客户端知道访问令牌过期，则跳到步骤G，肉则，它就会发出另一个对受保护资源的访问请求。

* (F) 由于访问令牌无效，资源服务器返回令牌无效的错误。

* (G) 客户端通过授权服务器进行身份验证并出示刷新令牌来获取新的访问令牌。对客户端认证的要求是基于客户端类型和授权服务器的策略。

* (H) 授权服务器对客户端进行认证，并验证刷新令牌，如果有效，则下发新的访问令牌（以及可选的新的刷新令牌）。


> The flow illustrated in Figure 2 includes the following steps:
>
>    (A)  The client requests an access token by authenticating with the
>         authorization server and presenting an authorization grant.
>
>    (B)  The authorization server authenticates the client and validates
>         the authorization grant, and if valid, issues an access token
>         and a refresh token.
>
>    (C)  The client makes a protected resource request to the resource
>         server by presenting the access token.
>
>    (D)  The resource server validates the access token, and if valid,
>         serves the request.
>
>    (E)  Steps (C) and (D) repeat until the access token expires.  If the
>         client knows the access token expired, it skips to step (G);
>         otherwise, it makes another protected resource request.
>
>    (F)  Since the access token is invalid, the resource server returns
>         an invalid token error.
>
>    (G)  The client requests a new access token by authenticating with
>         the authorization server and presenting the refresh token.  The
>         client authentication requirements are based on the client type
>         and on the authorization server policies.
>
>    (H)  The authorization server authenticates the client and validates
>         the refresh token, and if valid, issues a new access token (and,
>         optionally, a new refresh token).

如第7章节所述，步骤C、D、E和F不属于本规范的讨论范围。
> Steps (C), (D), (E), and (F) are outside the scope of this
>    specification, as described in Section 7.

## 1.6 TLS版本 - TLS Version

每当本规范提及使用TLS时，其适合的版本会随着时间推移、广泛性部署和已知安全漏洞而改变。在写这篇文章时，TLS 1.2版本[RFC5246]是最新的版本，但它的部署基础非常有限，且可能无法轻易实现。TLS 1.0版本[RFC2246]是部署最广泛的版本，将提供最广泛的可操作性。

> Whenever Transport Layer Security (TLS) is used by this
>    specification, the appropriate version (or versions) of > TLS will vary
>    over time, based on the widespread deployment and known > security
>    vulnerabilities.  At the time of this writing, TLS > version 1.2
>    [RFC5246] is the most recent version, but has a very > limited
>    deployment base and might not be readily available for
>    implementation.  TLS version 1.0 [RFC2246] is the most > widely
>    deployed version and will provide the broadest > interoperability.

实施机构也可以根据自己的安全需求，支持其它的传输层安全机制。

> Implementations MAY also support additional transport-layer security
>    mechanisms that meet their security requirements.

## 1.7 HTTP重定向 - HTTP Redirections

本规范广泛的使用了HTTP重定向，即客户端或授权服务器将资源所有者的用户代理引导到另一个地址。虽然本规范中的例子展示了HTTP 302状态码的使用，但其它的可以通过用户代理来完成这种重定向动作的方法也是允许的，并被认为是一种实施细节。

> This specification makes extensive use of HTTP redirections, in which
>    the client or the authorization server directs the resource owner's
>    user-agent to another destination.  While the examples in this
>    specification show the use of the HTTP 302 status code, any other
>    method available via the user-agent to accomplish this redirection is
>    allowed and is considered to be an implementation detail.

## 1.8 互操作性 - Interoperability

OAuth 2.0提供了一个具有良好安全属性定义的丰富的授权框架，然而，作为一个具有许多可选组件的丰富的、高度可扩展的框架，该规范本身可能产生广泛的不可互操作的实现。

> OAuth 2.0 provides a rich authorization framework with > well-defined
>    security properties.  However, as a rich and highly extensible
>    framework with many optional components, on its own, this
>    specification is likely to produce a wide range of non-interoperable
>    implementations.

此外，对本规范所需的一些组件，本规范仍然部分或完全的未对这些组件进行定义（如客户端注册、授权服务器功能、端点发现）。如果没有这些组件，客户端必须针对特定的授权服务器和资源服务器进行手动的配置，才能实现互操作。

> In addition, this specification leaves a few required components
>    partially or fully undefined (e.g., client registration,
>    authorization server capabilities, endpoint discovery).  Without
>    these components, clients must be manually and specifically
>    configured against a specific authorization server and resource
>    server in order to interoperate.

在设计该框架时，我们明确期望未来的工作将定义必要的规范性配置文件和扩展机制，以完整的实现web-scale。

> This framework was designed with the clear expectation that future
>    work will define prescriptive profiles and extensions necessary to
>    achieve full web-scale interoperability.

# 2. 客户端注册 - Client Registration

在使用本协议之前，客户端需要向授权服务器注册。客户端在授权服务器注册的方式超过了本协议的讨论范围，但是通常是采用最终用户与HTML注册表单交互的方式。

> Before initiating the protocol, the client registers with the
>    authorization server.  The means through which the client registers
>    with the authorization server are beyond the scope of this
>    specification but typically involve end-user interaction with an HTML
>    registration form.

客户端注册的实现不需要客户端与授权服务器进行直接交互。当授权服务器支持时，注册可以通过其他方式来建立信任并获取所需的客户端属性（如重定向URI、客户端类型等）。比如，注册可以通过自签名或第三方签发的断言实现，或者授权服务器可以通过可信任的信道来进行客户端发现。

> Client registration does not require a direct interaction between the
>    client and the authorization server.  When supported by the
>    authorization server, registration can rely on other means for
>    establishing trust and obtaining the required client properties
>    (e.g., redirection URI, client type).  For example, registration can
>    be accomplished using a self-issued or third-party-issued assertion,
>    or by the authorization server performing client discovery using a
>    trusted channel.

当注册为一个客户端时，客户端的开发人员应该：
* 如2.1章节所述，声明客户端类型，

* 如3.1.2章节所述，提供客户端的重定向URI，并且

* 携带授权服务器所需的其它信息（如：应用名、网站、描述、logo以及法律条款等）

> When registering a client, the client developer SHALL:
> * specify the client type as described in Section 2.1,
>
> * provide its client redirection URIs as described in Section 3.1.2,and
>
> * include any other information required by the authorization server
    (e.g., application name, website, description, logo image, the
    acceptance of legal terms).

## 2.1 客户端类型 - Client Types

基于客户端是否有能力与授权服务器进行安全认证的能力（即是否有能力保障其客户端凭证的保密性），OAuth定义了两种客户端类型：

私密客户端
能够保障其凭证的保密性的客户端（如在安全的服务器上部署的客户端，对其凭证的访问受到限制），或者有办法通过别的方式进行安全认证的客户端。

公开客户端
客户端无法保障其凭证的保密性（如客户端运行在资源所有者的设备上，比如是本地应用或基于web浏览器的应用），也无法通过别的方式进行安全认证的客户端。

> OAuth defines two client types, based on their ability to
>    authenticate securely with the authorization server (i.e., ability to
>    maintain the confidentiality of their client credentials):
>
>    confidential
>       Clients capable of maintaining the confidentiality of their
>       credentials (e.g., client implemented on a secure server with
>       restricted access to the client credentials), or capable of secure
>       client authentication using other means.
>
>    public
>       Clients incapable of maintaining the confidentiality of their
>       credentials (e.g., clients executing on the device used by the
>       resource owner, such as an installed native application or a web
>       browser-based application), and incapable of secure client
>       authentication via any other means.

客户端类型的指定是基于授权服务器对安全认证的定义，以及其可接受的对客户端凭证的暴露程度。授权服务器不应该对客户端类型进行假设。

> The client type designation is based on the authorization server's
>    definition of secure authentication and its acceptable exposure
>    levels of client credentials.  The authorization server SHOULD NOT
>    make assumptions about the client type.

客户端可能作为分布式组件的方式部署，每个组件可能具有不同的客户端类型和安全策略（比如，分布式客户端可能同时具备私密的server-based组件以及公开的browser-based组件）。如果授权服务器对这类客户端不提供支持，或者没有没有提供对其注册方式的知道，那么客户端应该对每个组件进行单独的注册。

> A client may be implemented as a distributed set of components, each
>    with a different client type and security context (e.g., a
>    distributed client with both a confidential server-based component
>    and a public browser-based component).  If the authorization server
>    does not provide support for such clients or does not provide
>    guidance with regard to their registration, the client SHOULD
>    register each component as a separate client.

本规范围绕以下的客户端特征进行设计：

web application
web应用程序是运行在web服务器上的私密客户端。资源所有者通过在自己设备上的用户代理渲染的HTML来访问客户端的用户界面。客户端凭证或者任何访问令牌都是存储在web服务器上，不会暴露给资源所有者。

user-agent-based application
基于用户代理的应用程序是公开客户端，客户端代码从web服务器下载，并在资源所有者的设备的用户代理（如web浏览器）中执行，协议的数据和客户端凭证对资源所有者而言是很容易访问的（并且经常是可见的）。由于这类应用程序驻留在用户代理中，因此在请求授权时可以无缝利用用户代理的功能。

native application
本地应用是指在资源所有者设备上安装并执行的应用，协议的数据和客户端凭证对资源所有者是可见的，可以假设该应用程序中的客户端认证凭证都是可以被提取的。另一方面，动态签发的凭证，比如访问令牌或刷新令牌，是可以受到可接受程度的保护的。至少，应保护这些凭据不受应用程序可能与之交互的敌对服务器的攻击。在某些平台上，可以保护这些凭据免受驻留在同一设备上的其他应用程序的攻击。

> This specification has been designed around the following client
>    profiles:
>
>    web application
>       A web application is a confidential client running on a web
>       server.  Resource owners access the client via an HTML user
>       interface rendered in a user-agent on the device used by the
>       resource owner.  The client credentials as well as any access
>       token issued to the client are stored on the web server and are
>       not exposed to or accessible by the resource owner.
>
>    user-agent-based application
>       A user-agent-based application is a public client in which the
>       client code is downloaded from a web server and executes within a
>       user-agent (e.g., web browser) on the device used by the resource
>       owner.  Protocol data and credentials are easily accessible (and
>       often visible) to the resource owner.  Since such applications
>       reside within the user-agent, they can make seamless use of the
>       user-agent capabilities when requesting authorization.
>
>    native application
>       A native application is a public client installed and executed on
>       the device used by the resource owner.  Protocol data and
>       credentials are accessible to the resource owner.  It is assumed
>       that any client authentication credentials included in the
>       application can be extracted.  On the other hand, dynamically
>       issued credentials such as access tokens or refresh tokens can
>       receive an acceptable level of protection.  At a minimum, these
>       credentials are protected from hostile servers with which the
>       application may interact.  On some platforms, these credentials
>       might be protected from other applications residing on the same
>       device.

## 2.2 客户端标识 - Client Identifier

授权服务器为注册的客户端签发客户端标识，该标识是代表客户端注册信息的唯一的字符串。客户端凭证并不私密，它会暴露给资源所有者，并且不能仅以来该凭证进行客户端认证。客户端凭证对授权服务器是唯一的。

> The authorization server issues the registered client a client
>    identifier -- a unique string representing the registration
>    information provided by the client.  The client identifier is not a
>    secret; it is exposed to the resource owner and MUST NOT be used
>    alone for client authentication.  The client identifier is unique to
>    the authorization server.

客户端标识符的大小未在本规范中定义，客户端不应该揣测该凭证的大小。授权服务器应该记录它发布的任何凭证的大小。

> The client identifier string size is left undefined by this
>    specification.  The client should avoid making assumptions about the
>    identifier size.  The authorization server SHOULD document the size
>    of any identifier it issues.

不建议使用两个参数在请求正文中包含客户端凭据，并且应仅限于无法直接使用HTTP Basic身份验证方案（或其他基于密码的HTTP身份验证方案）的客户端。参数只能在请求正文中传输，并且不得包含在请求URI中。

> Including the client credentials in the request-body using the two
>    parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
>    to directly utilize the HTTP Basic authentication scheme (or other
>    password-based HTTP authentication schemes).  The parameters can only
>    be transmitted in the request-body and MUST NOT be included in the
>    request URI.

例如，在刷新access token请求的请求体中包含参数的情况：

    POST /token HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
    &client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw

> For example, a request to refresh an access token (Section 6) using
>    the body parameters (with extra line breaks for display purposes
>    only):
>
>      POST /token HTTP/1.1
>      Host: server.example.com
>      Content-Type: application/x-www-form-urlencoded
>
>      grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
>      &client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw

使用密码进行认证时，授权服务器必须按照1.6章节中所述使用TLS。

> The authorization server MUST require the use of TLS as described in
>    Section 1.6 when sending requests using password authentication.

由于客户端认证的方法涉及密码，因此授权服务器必须保证相关端点都可以抵御暴力攻击。

> Since this client authentication method involves a password, the
>    authorization server MUST protect any endpoint utilizing it against
>    brute force attacks.

## 2.3 客户端认证 - Client Authentication

如果客户端类型为私密类型，那客户端和授权服务器将建立符合授权服务器安全要求的认证方法。授权服务器可以接受满足其安全要求的任何形式的客户端认证。

> If the client type is confidential, the client and authorization
>    server establish a client authentication method suitable for the
>    security requirements of the authorization server.  The authorization
>    server MAY accept any form of client authentication meeting its
>    security requirements.

私密客户端通常会签发一组用于与授权服务器进行认证的客户端凭证（如密码、公私钥对等）。

> Confidential clients are typically issued (or establish) a set of
>    client credentials used for authenticating with the authorization
>    server (e.g., password, public/private key pair).

授权服务器也可以与公开客户端建立客户端认证的方法，但授权服务器不得出于识别客户端身份的目的来建立公开客户端的认证。

> The authorization server MAY establish a client authentication method
>    with public clients.  However, the authorization server MUST NOT rely
>    on public client authentication for the purpose of identifying the
>    client.

客户端在每个请求中不得使用超过一种的认证方法。

> The client MUST NOT use more than one authentication method in each
>    request.


### 2.3.1 客户端密码 - Client Password

拥有客户端密码的客户端可以使用[RFC2617]中定义的HTTP Basic认证方案来对与授权服务器进行认证，客户端凭证使用附录B中定义的"application/x-www-form-urlencoded"算法进行编码，并将编码后的结果作为用户名使用，客户端密码也是使用同样的算法进行编码，编码后的结果作为密码使用。授权服务器必须支持HTTP Basic身份验证方案，以对发布了客户端密码的客户端进行身份验证。

> Clients in possession of a client password MAY use the HTTP Basic
>    authentication scheme as defined in [RFC2617] to authenticate with
>    the authorization server.  The client identifier is encoded using the
>    "application/x-www-form-urlencoded" encoding algorithm per
>    Appendix B, and the encoded value is used as the username; the client
>    password is encoded using the same algorithm and used as the
>    password.  The authorization server MUST support the HTTP Basic
>    authentication scheme for authenticating clients that were issued a
>    client password.

比如（换行符仅用于展示目的）：

Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

> For example (with extra line breaks for display purposes only):
>
>    Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

或者，授权服务器也可以支持通过以下参数在请求体中包含客户端凭证：

client_id
要求。如2.2章节所述，在客户端注册时签发的客户端身份标识。

client_secret
要求。客户端密钥，如果客户端密钥是空的，那客户端可以忽略他。

> Alternatively, the authorization server MAY support including the
>    client credentials in the request-body using the following
>    parameters:
>
>    client_id
>          REQUIRED.  The client identifier issued to the client during
>          the registration process described by Section 2.2.
>
>    client_secret
>          REQUIRED.  The client secret.  The client MAY omit the
>          parameter if the client secret is an empty string.


### 2.3.2 其它认证方法 - Other Authentication Methods

授权服务器可以支持任何满足其安全要求的基于HTTP的认证方案。当使用其它认证方案时，授权服务器必须建立客户端标识（客户端注册记录）和授权方案的映射。

> The authorization server MAY support any suitable HTTP authentication
>    scheme matching its security requirements.  When using other
>    authentication methods, the authorization server MUST define a
>    mapping between the client identifier (registration record) and
>    authentication scheme.

## 2.4 未注册客户端 - Unregistered Clients

本规范不排斥使用未注册的客户端，但对此类客户端的使用超出本规范的讨论范围，并且需要额外的安全分析，并讨论其对互操作性的影响。

> This specification does not exclude the use of unregistered clients.
>    However, the use of such clients is beyond the scope of this
>    specification and requires additional security analysis and review of
>    its interoperability impact.


# 3. 协议端点 - Protocol Endpoints

授权过程中使用了两个授权服务器端点：

* 授权端点： 用于客户端通过用户代理（译者注：一般指浏览器）重定向的方式来向资源所有者索要授权许可。

* 令牌端点： 用于客户端通过授权许可去交换访问令牌，通常会同时进行客户端认证。

> The authorization process utilizes two authorization server endpoints
>    (HTTP resources):
>
>    o  Authorization endpoint - used by the client to obtain
>       authorization from the resource owner via user-agent redirection.
>
>    o  Token endpoint - used by the client to exchange an authorization
>       grant for an access token, typically with client authentication.

同时也需要使用一个客户端端点：

* 重定向端点： 授权服务器通过资源所有者的用户代理，将授权凭证返回给客户端（译者注：重定向的方式）。

> As well as one client endpoint:
>
>    o  Redirection endpoint - used by the authorization server to return
>       responses containing authorization credentials to the client via
>       the resource owner user-agent.

并非每一种授权类型都需要使用这些端点，而扩展授权类型可能根据需要定义其它的端点。

> Not every authorization grant type utilizes both endpoints.
>    Extension grant types MAY define additional endpoints as needed.

## 3.1 授权端点 - Authorization Endpoint

授权端点用于与资源所有者交互以获取授权许可。授权服务器必须先验证资源所有者的身份，其具体的验证方式（如用户名密码登录、session cookies等）超出了本规范的讨论范围。

> The authorization endpoint is used to interact with the resource
>    owner and obtain an authorization grant.  The authorization server
>    MUST first verify the identity of the resource owner.  The way in
>    which the authorization server authenticates the resource owner
>    (e.g., username and password login, session cookies) is beyond the
>    scope of this specification.

客户端通过何种方式来获取授权端点的位置超出了本规范的讨论范围，但一般会在服务目录里提供。

> The means through which the client obtains the location of the
>    authorization endpoint are beyond the scope of this specification,
>    but the location is typically provided in the service documentation.

授权端点的URI可能包含"application/x-www-form-urlencoded"的查询组件（[RFC3986] 章节3.4）（译者注：query component 是URI以'?'开始，以'#'结束的部分），如果有额外的查询参数，则必须包含这部分，相反，授权端点不得包含fragment组件（译者注：以'#'开始直到URI尾部的部分）。

> The endpoint URI MAY include an "application/x-www-form-urlencoded"
>    formatted (per Appendix B) query component ([RFC3986] Section 3.4),
>    which MUST be retained when adding additional query parameters.  The
>    endpoint URI MUST NOT include a fragment component.

由于发往授权端点的请求涉及用户认证和明文的凭证传输（在HTTP响应中），因此授权服务器必须如章节1.6所述使用TLS。

> Since requests to the authorization endpoint result in user
>    authentication and the transmission of clear-text credentials (in the
>    HTTP response), the authorization server MUST require the use of TLS
>    as described in Section 1.6 when sending requests to the
>    authorization endpoint.

授权服务器提供的授权端点必须支持HTTP "GET"类型的请求 [RFC2616]，同时也可以选择支持"POST"类型的请求。

> The authorization server MUST support the use of the HTTP "GET"
>    method [RFC2616] for the authorization endpoint and MAY support the
>    use of the "POST" method as well.

必须忽略参数值为空或未定义的参数，请求或响应中的参数名不得重复。

> Parameters sent without a value MUST be treated as if they were
>    omitted from the request.  The authorization server MUST ignore
>    unrecognized request parameters.  Request and response parameters
>    MUST NOT be included more than once.


### 3.1.1 响应类型 - Response Type

授权端点用于授权码模式以及隐式授权模式，客户端通过提供如下参数来告知授权服务器其所需的授权模式：

response_type
要求。若为授权码模式，则如章节4.1.1所述，传递“code”值，若为隐式授权模式，则如4.2.1节所述，传递“token”值，或者如8.4章节所述，为扩展类型。

> The authorization endpoint is used by the authorization code grant
>    type and implicit grant type flows.  The client informs the
>    authorization server of the desired grant type using the following
>    parameter:
> response_type
>          REQUIRED.  The value MUST be one of "code" for requesting an
>          authorization code as described by Section 4.1.1, "token" for
>          requesting an access token (implicit grant) as described by
>          Section 4.2.1, or a registered extension value as described by
>          Section 8.4.

扩展的响应类型可能会包含由空格分隔的值的列表，列表中的值是顺序无关的（如，"a b"等同于"b a"），这些组合形式响应类型的意义在其各自的规范中有定义。

> Extension response types MAY contain a space-delimited (%x20) list of
>    values, where the order of values does not matter (e.g., response
>    type "a b" is the same as "b a").  The meaning of such composite
>    response types is defined by their respective specifications.

如果授权请求中未包含"response_type"参数，或者其值是错误的，则授权服务器需如章节4.1.2.1所述，返回相应的错误响应。

> If an authorization request is missing the "response_type" parameter,
>    or if the response type is not understood, the authorization server
>    MUST return an error response as described in Section 4.1.2.1.

### 3.1.2 重定向端点 - Redirection Endpoint

当授权服务器完成与资源所有者的交互后，授权服务器会将资源所有者的user-agent重定向回客户端，这个重定向的端点是客户端注册时发布的端点，或是在授权请求时发送的端点。

> After completing its interaction with the resource owner, the
>    authorization server directs the resource owner's user-agent back to
>    the client.  The authorization server redirects the user-agent to the
>    client's redirection endpoint previously established with the
>    authorization server during the client registration process or when
>    making the authorization request.

重定向的URI必须是[RFC3986]中定义的绝对URI，如果需要添加额外的参数，则该端点需要包含"application/x-www-form-urlencoded"格式的查询组件([RFC3986]章节3.4)，该端点不可包含fragement组件。

> The redirection endpoint URI MUST be an absolute URI as defined by
>    [RFC3986] Section 4.3.  The endpoint URI MAY include an
>    "application/x-www-form-urlencoded" formatted (per Appendix B) query
>    component ([RFC3986] Section 3.4), which MUST be retained when adding
>    additional query parameters.  The endpoint URI MUST NOT include a
>    fragment component.

#### 3.1.2.1 授权请求保密性 - Endpoint Request Confidentiality

当请求的响应类型为"code"或"token"，或者重定向的请求需要在公网传递敏感的凭证数据时，必须要求重定向端点按章节1.6所述使用TLS连接。由于在编写本规范时，对开发者而言部署TLS是相对艰难的任务，因此本规范并未做强制要求。但如果TLS不可用，那授权服务器需要在重定向到该端点前，提示资源所有者该动作并不安全。(如，在授权请求时展示一个警告消息)

> The redirection endpoint SHOULD require the use of TLS as described
>    in Section 1.6 when the requested response type is "code" or "token",
>    or when the redirection request will result in the transmission of
>    sensitive credentials over an open network.  This specification does
>    not mandate the use of TLS because at the time of this writing,
>    requiring clients to deploy TLS is a significant hurdle for many
>    client developers.  If TLS is not available, the authorization server
>    SHOULD warn the resource owner about the insecure endpoint prior to
>    redirection (e.g., display a message during the authorization
>    request).

传输层的安全缺陷，会严重影响客户端及其授权访问的受保护资源的安全，当客户端将授权过程作为其最终用户认证的一种方式时(如第三方登录服务)，保证传输层安全会尤为重要。

> Lack of transport-layer security can have a severe impact on the
>    security of the client and the protected resources it is authorized
>    to access.  The use of transport-layer security is particularly
>    critical when the authorization process is used as a form of
>    delegated end-user authentication by the client (e.g., third-party
>    sign-in service).

#### 3.1.2.2 注册条件 - Registration Requirements

授权服务器要求如下类型的客户端登记他们的重定向端点：

* 公开客户端

* 使用隐式授权模式的非公开客户端

> The authorization server MUST require the following clients to
>    register their redirection endpoint:
>
>    o  Public clients.
>
>    o  Confidential clients utilizing the implicit grant type.

授权服务器要求所有客户端在使用授权端点前，登记他们的重定向端点。

> The authorization server SHOULD require all clients to register their
>    redirection endpoint prior to utilizing the authorization endpoint.

授权服务器应该要求客户端提供完成的重定向URI(客户端可能会使用"state"参数来防范CSRF)。如果要求注册完整的重定向的URI并不现实，那授权服务器必须要求注册URI scheme、authority和path(只允许客户端动态的修改重定向URI的查询组件的参数)。

> The authorization server SHOULD require the client to provide the
>    complete redirection URI (the client MAY use the "state" request
>    parameter to achieve per-request customization).  If requiring the
>    registration of the complete redirection URI is not possible, the
>    authorization server SHOULD require the registration of the URI
>    scheme, authority, and path (allowing the client to dynamically vary
>    only the query component of the redirection URI when requesting
>    authorization).

授权服务器允许客户端注册多个重定向端点。

> The authorization server MAY allow the client to register multiple
>    redirection endpoints.

缺乏对重定向URI的注册管理机制，可能导致如10.15章节所描述的攻击者使用授权端点作为公共转向器的问题(译者注：不准确)。

> Lack of a redirection URI registration requirement can enable an
>    attacker to use the authorization endpoint as an open redirector as
>    described in Section 10.15.

#### 3.1.2.3 动态配置 - Dynamic Configuration

在如下情况下，客户端需要在授权请求时携带"redirect_uri"参数：
* 注册了多个重定向端点
* 注册了重定向端点的某部分(译者注：如上所述，并未注册完整的URI)
* 没有注册重定向端点

> If multiple redirection URIs have been registered, if only part of
>    the redirection URI has been registered, or if no redirection URI has
>    been registered, the client MUST include a redirection URI with the
>    authorization request using the "redirect_uri" request parameter.

如果注册过重定向URI，那当授权请求中包含重定向URI(或URI组件)时，授权服务器必须将接收到的值与注册值进行对比(如[RFC3986]第6章节所定义)，如果客户端注册的是完整的重定向URI，那授权服务器应如[RFC3986]第6.2.1章节所述对其进行简单的字符串对比校验。

> When a redirection URI is included in an authorization request, the
>    authorization server MUST compare and match the value received
>    against at least one of the registered redirection URIs (or URI
>    components) as defined in [RFC3986] Section 6, if any redirection
>    URIs were registered.  If the client registration included the full
>    redirection URI, the authorization server MUST compare the two URIs
>    using simple string comparison as defined in [RFC3986] Section 6.2.1.

#### 3.1.2.4 无效的端点 - Invalid Endpoint

如果授权请求因为丢失或包含无效、不匹配的重定向URI而导致失败，则授权服务器必须提示资源所有者失败原因，而非自动将user-agent重定向到无效的URI。

> If an authorization request fails validation due to a missing,
>    invalid, or mismatching redirection URI, the authorization server
>    SHOULD inform the resource owner of the error and MUST NOT
>    automatically redirect the user-agent to the invalid redirection URI.

#### 3.1.2.5 端点内容 - Endpoint Content

客户端的重定向请求的响应通常是HTML的形式，由user-agent处理，如果该HTML响应是直接作为重定向请求的结果，那么该HTML中包含的脚本将有权限访问该重定向URI及其包含的凭证数据。

> The redirection request to the client's endpoint typically results in
>    an HTML document response, processed by the user-agent.  If the HTML
>    response is served directly as the result of the redirection request,
>    any script included in the HTML document will execute with full
>    access to the redirection URI and the credentials it contains.

## 3.2 Token端点 - Token Endpoint

Token端点用于让客户端获取access token，可以通过出示授权许可和refresh token两种形式。除隐式授权模式外(直接签发access token)，其余授权模式都会使用token端点。

> The token endpoint is used by the client to obtain an access token by
>    presenting its authorization grant or refresh token.  The token
>    endpoint is used with every authorization grant except for the
>    implicit grant type (since an access token is issued directly).

关于客户端如何获取token端点的地址的问题，超出了该文档的讨论范围，但一般是由服务目录提供。

> The means through which the client obtains the location of the token
>    endpoint are beyond the scope of this specification, but the location
>    is typically provided in the service documentation.

该端点的URI如需携带参数，则需包含"application/x-www-form-urlencoded"格式的查询组件([RFC3986] 3.4章节)，该端点不允许包含fragment组件。

> The endpoint URI MAY include an "application/x-www-form-urlencoded"
>    formatted (per Appendix B) query component ([RFC3986] Section 3.4),
>    which MUST be retained when adding additional query parameters.  The
>    endpoint URI MUST NOT include a fragment component.

由于访问token端点的请求或响应都涉及明文凭证的传输，因此必须对token端点使用1.6章节所述的TLS连接。

> Since requests to the token endpoint result in the transmission of
>    clear-text credentials (in the HTTP request and response), the
>    authorization server MUST require the use of TLS as described in
>    Section 1.6 when sending requests to the token endpoint.

客户端必须使用"POST"方式来发起获取access token的请求。

> The client MUST use the HTTP "POST" method when making access token
>    requests.

当参数值为空或是未定义的参数时，授权服务器必须忽略该参数，请求或响应中的参数不得重复。

> Parameters sent without a value MUST be treated as if they were
>    omitted from the request.  The authorization server MUST ignore
>    unrecognized request parameters.  Request and response parameters
>    MUST NOT be included more than once.

### 3.2.1 客户端认证 - Client Authentication

非公开客户端或其它签发了客户端凭证的客户端，在访问token端点时必须如章节2.3所述由授权服务器进行客户端认证，客户端认证的作用是：

* 确保refresh token和授权码确实是由签发的客户端来使用的。当在不受信的链路传输授权码，或者未注册完整的重定向URI的场景下，客户端验证尤为重要。

* 通过禁用客户端或修改客户端的凭证来恢复被入侵的客户端，从而防止攻击者滥用窃取的refresh token。修改一组客户端凭证显然比撤销整组刷新令牌要快得多。

* 实施认证管理的最佳实践，是定期进行凭证的轮换。整套刷新令牌的轮换可能具有挑战性，而单套客户端凭证的轮换则容易得多。

> Confidential clients or other clients issued client credentials MUST
>    authenticate with the authorization server as described in
>    Section 2.3 when making requests to the token endpoint.  Client
>    authentication is used for:
>
>    o  Enforcing the binding of refresh tokens and authorization codes to
>       the client they were issued to.  Client authentication is critical
>       when an authorization code is transmitted to the redirection
>       endpoint over an insecure channel or when the redirection URI has
>       not been registered in full.
>
>    o  Recovering from a compromised client by disabling the client or
>       changing its credentials, thus preventing an attacker from abusing
>       stolen refresh tokens.  Changing a single set of client
>       credentials is significantly faster than revoking an entire set of
>       refresh tokens.
>
>    o  Implementing authentication management best practices, which
>       require periodic credential rotation.  Rotation of an entire set
>       of refresh tokens can be challenging, while rotation of a single
>       set of client credentials is significantly easier.

当向token端点发送请求时，客户端必须使用"client_id"参数来标识自己，当grant_type为authorization_code时，未认证的客户端必须发送"client_id"参数来防止它接收到其它client的code，这可以保证客户端不会被替换code(没有为受保护的资源提供额外的安全保障)。

> A client MAY use the "client_id" request parameter to identify itself
>    when sending requests to the token endpoint.  In the
>    "authorization_code" "grant_type" request to the token endpoint, an
>    unauthenticated client MUST send its "client_id" to prevent itself
>    from inadvertently accepting a code intended for a client with a
>    different "client_id".  This protects the client from substitution of
>    the authentication code.  (It provides no additional security for the
>    protected resource.)

### 3.3 访问令牌的范围 - Access Token Scope

授权和令牌端点允许客户端通过使用"scope"参数来声明其访问范围，相应的，授权服务器也通过"scope"相应参数来指明为客户端签发的access token的授权访问范围。

> The authorization and token endpoints allow the client to specify the
>    scope of the access request using the "scope" request parameter.  In
>    turn, the authorization server uses the "scope" response parameter to
>    inform the client of the scope of the access token issued.

scope参数的值是空格分割且大小写敏感的字符串，这些字符串的值是有授权服务器定义的，如果scope的值包含多个空格分割的字符串，那这些字符串值是顺序无关的，并且所有的字符串都会为请求的作用域增加额外的访问范围。

> The value of the scope parameter is expressed as a list of space-
>    delimited, case-sensitive strings.  The strings are defined by the
>    authorization server.  If the value contains multiple space-delimited
>    strings, their order does not matter, and each string adds an
>    additional access range to the requested scope.

scope       = scope-token *( SP scope-token )
scope-token = 1*( %x21 / %x23-5B / %x5D-7E )

授权服务器可以根据授权服务器策略或资源所有者的指示，完全或部分的忽略客户端请求的作用域，如果发出的访问令牌范围与客户端请求的范围不同，则授权服务器必须包含"scope"响应参数，以告知客户端实际授予的范围。

> The authorization server MAY fully or partially ignore the scope
>    requested by the client, based on the authorization server policy or
>    the resource owner's instructions.  If the issued access token scope
>    is different from the one requested by the client, the authorization
>    server MUST include the "scope" response parameter to inform the
>    client of the actual scope granted.

如果客户端在授权时忽略了scope参数，则授权服务器必须用预定义的默认值来填充，或直接告知客户端使用了无效的scope。如有定义，授权服务器需要注明其对scope的要求和默认值。

> If the client omits the scope parameter when requesting
>    authorization, the authorization server MUST either process the
>    request using a pre-defined default value or fail the request
>    indicating an invalid scope.  The authorization server SHOULD
>    document its scope requirements and default value (if defined).

# 4.获取授权 - Obtaining Authorization

为了获取访问令牌，客户端需要向资源所有者索要授权。授权以授权许可的形式来表示，客户端以此来请求访问令牌。OAuth定义了四中授权类型：授权码、隐式、资源所有者密码凭证以及客户端凭证。同时它也提供一个扩展机制来定义其他的授权类型。

> To request an access token, the client obtains authorization from the
>    resource owner.  The authorization is expressed in the form of an
>    authorization grant, which the client uses to request the access
>    token.  OAuth defines four grant types: authorization code, implicit,
>    resource owner password credentials, and client credentials.  It also
>    provides an extension mechanism for defining additional grant types.

## 4.1 授权码模式 - Authorization Code Grant

授权码模式可用于同时获取访问令牌和刷新令牌，对非公开客户端也有所优化。由于该模式依赖重定向，因此客户端必须具备同资源所有者的user-agent(典型的如web浏览器)交互的能力，同时也要具备接收授权服务器请求的能力(通过重定向)。

> The authorization code grant type is used to obtain both access
>    tokens and refresh tokens and is optimized for confidential clients.
>    Since this is a redirection-based flow, the client must be capable of
>    interacting with the resource owner's user-agent (typically a web
>    browser) and capable of receiving incoming requests (via redirection)
>    from the authorization server.

     +----------+
     | Resource |
     |   Owner  |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier      +---------------+
     |         -+----(A)-- & Redirection URI ---->|               |
     |  User-   |                                 | Authorization |
     |  Agent  -+----(B)-- User authenticates --->|     Server    |
     |          |                                 |               |
     |         -+----(C)-- Authorization Code ---<|               |
     +-|----|---+                                 +---------------+
       |    |                                         ^      v
      (A)  (C)                                        |      |
       |    |                                         |      |
       ^    v                                         |      |
     +---------+                                      |      |
     |         |>---(D)-- Authorization Code ---------'      |
     |  Client |          & Redirection URI                  |
     |         |                                             |
     |         |<---(E)----- Access Token -------------------'
     +---------+       (w/ Optional Refresh Token)

图3中的图示包含如下步骤：

    (A) 客户端通过将资源所有者的user-agent重定向到授权端点来初始化授权码流程，客户端需要携带客户端标识、请求授权的范围、state以及重定向URI（当授权通过或拒绝时，授权服务器将user-agent重定向回该URI）。

    (B) 授权服务器对资源所有者进行认证，并确认资源所有者是授权还是拒绝客户端的访问请求。

    (C) 假设资源所有者授权允许客户端的访问，授权服务器会将user-agent重定向到之前提供的重定向URI（授权请求中或者客户端注册时提供的），重定向URI中会包含授权码，以及之前客户端提供的state参数。

    (D) 客户端通过上述步骤中获取的授权码，向授权服务器请求访问令牌。当发起该请求时，客户端需要进行身份认证，此外，参数中也需要包含换取授权码时携带的重定向URI，以作为验证。

    (E) 授权服务器对客户端进行认证，验证授权码是否正确，并确保重定向URI与步骤C中的完全匹配，如果验证通过，授权服务器将返回访问令牌，也可能包含刷新令牌。


> The flow illustrated in Figure 3 includes the following steps:
>
>    (A)  The client initiates the flow by directing the resource owner's
>         user-agent to the authorization endpoint.  The client includes
>         its client identifier, requested scope, local state, and a
>         redirection URI to which the authorization server will send the
>         user-agent back once access is granted (or denied).
>
>    (B)  The authorization server authenticates the resource owner (via
>         the user-agent) and establishes whether the resource owner
>         grants or denies the client's access request.
>
>    (C)  Assuming the resource owner grants access, the authorization
>         server redirects the user-agent back to the client using the
>         redirection URI provided earlier (in the request or during
>         client registration).  The redirection URI includes an
>         authorization code and any local state provided by the client
>         earlier.
>
>    (D)  The client requests an access token from the authorization
>         server's token endpoint by including the authorization code
>         received in the previous step.  When making the request, the
>         client authenticates with the authorization server.  The client
>         includes the redirection URI used to obtain the authorization
>         code for verification.
>
>    (E)  The authorization server authenticates the client, validates the
>         authorization code, and ensures that the redirection URI
>         received matches the URI used to redirect the client in
>         step (C).  If valid, the authorization server responds back with
>         an access token and, optionally, a refresh token.

### 4.1.1 授权请求 - Authorization Request

客户端使用附录B中说明的"application/x-www-form-urlencoded"格式，去构造授权端点的请求参数：

    response_type
        必须。值必须为"code"。

    client_id
        必须。章节2.2中描述的客户端标识。

    redirect_uri
        可选。章节3.1.2中有描述。

    scope
        可选。章节3.3中描述的请求访问的范围。

    state
        建议。客户端用来维护请求和回调之间状态的不透明值。授权服务器将user-agent重定向回客户端时会携带该值。该值一般用于防止章节10.12中的跨站请求伪造攻击。

> The client constructs the request URI by adding the following
>    parameters to the query component of the authorization endpoint URI
>    using the "application/x-www-form-urlencoded" format, per Appendix B:
>
>    response_type
>          REQUIRED.  Value MUST be set to "code".
>
>    client_id
>          REQUIRED.  The client identifier as described in Section 2.2.
>
>    redirect_uri
>          OPTIONAL.  As described in Section 3.1.2.
>
>    scope
>          OPTIONAL.  The scope of the access request as described by
>          Section 3.3.
>
>    state
>          RECOMMENDED.  An opaque value used by the client to maintain
>          state between the request and callback.  The authorization
>          server includes this value when redirecting the user-agent back
>          to the client.  The parameter SHOULD be used for preventing
>          cross-site request forgery as described in Section 10.12.

客户端通过HTTP重定向的响应或其它可行的方式，将资源所有者的user-agent引导到构造的URI。

> The client directs the resource owner to the constructed URI using an
>    HTTP redirection response, or by other means available to it via the
>    user-agent.

比如，客户端引导user-agent通过TLS发起如下请求：

    GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
    Host: server.example.com

> For example, the client directs the user-agent to make the following
>    HTTP request using TLS (with extra line breaks for display purposes
>    only):
>
>     GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
>         &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
>     Host: server.example.com

授权服务器验证授权请求，以确保所有必须的参数都已提供并且经过验证，如果验证通过，授权服务器将验证资源所有者的身份，并获取其是否授权的决定（通过询问资源所有者，或建立其它的同意机制）。

> The authorization server validates the request to ensure that all
>    required parameters are present and valid.  If the request is valid,
>    the authorization server authenticates the resource owner and obtains
>    an authorization decision (by asking the resource owner or by
>    establishing approval via other means).

当用户完成其授权决策后，授权服务器将通过HTTP重定向或其它可行的方式，将user-agent引导到重定向URI。

> When a decision is established, the authorization server directs the
>    user-agent to the provided client redirection URI using an HTTP
>    redirection response, or by other means available to it via the
>    user-agent.

### 4.1.2 授权响应 - Authorization Response

如果资源所有者授予了访问权限，授权服务器将签发一个授权码，并且通过附录B中定义的"application/x-www-form-urlencoded"格式将如下参数组织到重定向URI的查询参数中。

    code
        必须。授权码由授权服务器生成，且授权码不应该维持太长时间，以减小泄露的风险，一般建议最长维持10分钟。客户端不能多次使用同一个授权码，如果某个授权码出现多次使用的情况，授权服务器应该拒绝当前的请求，并且吊销由该授权码签发的所有令牌。授权码与客户端标识和重定向URI存在绑定关系。

    state
        必须。该值为客户端发起授权请求时传递的值（有传则在此时返回）。

> If the resource owner grants the access request, the authorization
>    server issues an authorization code and delivers it to the client by
>    adding the following parameters to the query component of the
>    redirection URI using the "application/x-www-form-urlencoded" format,
>    per Appendix B:
>
>    code
>          REQUIRED.  The authorization code generated by the
>          authorization server.  The authorization code MUST expire
>          shortly after it is issued to mitigate the risk of leaks.  A
>          maximum authorization code lifetime of 10 minutes is
>          RECOMMENDED.  The client MUST NOT use the authorization code
>          more than once.  If an authorization code is used more than
>          once, the authorization server MUST deny the request and SHOULD
>          revoke (when possible) all tokens previously issued based on
>          that authorization code.  The authorization code is bound to
>          the client identifier and redirection URI.
>
>    state
>          REQUIRED if the "state" parameter was present in the client
>          authorization request.  The exact value received from the
>          client.

例如，授权服务器会通过如下HTTP响应对user-agent进行重定向动作：

    HTTP/1.1 302 Found
    Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
               &state=xyz

> For example, the authorization server redirects the user-agent by
>    sending the following HTTP response:
>
>      HTTP/1.1 302 Found
>      Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
>                &state=xyz

客户端必须忽略无法识别的响应参数。此规范未定义授权码字符串的长度，因此客户端应避免预设授权码的长度。授权服务器应该记录所有签发的值的长度。

> The client MUST ignore unrecognized response parameters.  The
>    authorization code string size is left undefined by this
>    specification.  The client should avoid making assumptions about code
>    value sizes.  The authorization server SHOULD document the size of
>    any value it issues.

#### 4.1.2.1 错误响应 - Error Response

如果授权请求由于重定向URI或客户端标识参数存在问题（丢失、无效或不匹配）导致请求失败，授权服务器应该告知资源所有者出现异常，而不是自动将user-agent重定向到无效的重定向URI。

> If the request fails due to a missing, invalid, or mismatching
>    redirection URI, or if the client identifier is missing or invalid,
>    the authorization server SHOULD inform the resource owner of the
>    error and MUST NOT automatically redirect the user-agent to the
>    invalid redirection URI.

如果资源所有者拒绝授权，或出现除丢失、无效重定向URI以外的异常，授权服务器应该通过附录B描述的"application/x-www-form-urlencoded"格式，通过以下参数告知客户端异常原因：

    error
        必须。值为如下简单的ASCII错误码：

        invalid_request
            缺少必须的参数，包含无效的参数值，使用同名参数，以及其它问题。

        unauthorized_client
            客户端没有使用该方法获取授权码的权限。

        access_denied
            资源所有者拒绝授权。

        unsupported_response_type
            授权服务器不支持通过该方法获取授权码。

        invalid_scope
            请求的授权范围无效或未定义。

        server_error
            授权服务器发生意外情况，无法完成请求（之所以需要该错误代码，是因为无法通过HTTP重定向将500内部服务器错误状态返回给客户端）。

        temporarily_unavailable
            由于服务器临时过载或维护，授权服务器当前无法处理该请求（之所以需要该错误代码，是因为无法通过HTTP重定向将503服务器不可用状态返回给客户端）。

        error参数值包含的字符必须在%x20-21 / %x23-5B / %x5D-7E范围内。

    error_description
        可选。可理解的ASCII文本，用于提供额外的信息，帮助客户端开发者理解发生了何种异常。
        error_description参数值包含的字符必须在%x20-21 / %x23-5B / %x5D-7E范围内。
    
    error_uri
        可选。包含错误信息的web界面的URI，用于向客户端开发人员提供额外的错误信息。
        error_uri参数值必须符合URI-reference语法，并且包含的字符必须在%x21 / %x23-5B / %x5D-7E范围内。

    state
        如果客户端在授权请求中携带该参数，则必须原样返回。

> If the resource owner denies the access request or if the request
>    fails for reasons other than a missing or invalid redirection URI,
>    the authorization server informs the client by adding the following
>    parameters to the query component of the redirection URI using the
>    "application/x-www-form-urlencoded" format, per Appendix B:
>
>    error
>          REQUIRED.  A single ASCII [USASCII] error code from the
>          following:
>
>          invalid_request
>                The request is missing a required parameter, includes an
>                invalid parameter value, includes a parameter more than
>                once, or is otherwise malformed.
>
>          unauthorized_client
>                The client is not authorized to request an authorization
>                code using this method.
>
>          access_denied
>                The resource owner or authorization server denied the
>                request.
>
>          unsupported_response_type
>                The authorization server does not support obtaining an
>                authorization code using this method.
>
>          invalid_scope
>                The requested scope is invalid, unknown, or malformed.
>
>          server_error
>                The authorization server encountered an unexpected
>                condition that prevented it from fulfilling the request.
>                (This error code is needed because a 500 Internal Server
>                Error HTTP status code cannot be returned to the client
>                via an HTTP redirect.)
>
>          temporarily_unavailable
>                The authorization server is currently unable to handle
>                the request due to a temporary overloading or maintenance
>                of the server.  (This error code is needed because a 503
>                Service Unavailable HTTP status code cannot be returned
>                to the client via an HTTP redirect.)
>
>          Values for the "error" parameter MUST NOT include characters
>          outside the set %x20-21 / %x23-5B / %x5D-7E.
>
>    error_description
>          OPTIONAL.  Human-readable ASCII [USASCII] text providing
>          additional information, used to assist the client developer in
>          understanding the error that occurred.
>          Values for the "error_description" parameter MUST NOT include
>          characters outside the set %x20-21 / %x23-5B / %x5D-7E.
>
>    error_uri
>          OPTIONAL.  A URI identifying a human-readable web page with
>          information about the error, used to provide the client
>          developer with additional information about the error.
>          Values for the "error_uri" parameter MUST conform to the
>          URI-reference syntax and thus MUST NOT include characters
>          outside the set %x21 / %x23-5B / %x5D-7E.
>
>    state
>          REQUIRED if a "state" parameter was present in the client
>          authorization request.  The exact value received from the
>          client.

比如，授权服务器通过如下HTTP响应对user-agent进行重定向：

    HTTP/1.1 302 Found
    Location: https://client.example.com/cb?error=access_denied&state=xyz

> For example, the authorization server redirects the user-agent by
>    sending the following HTTP response:
>
>    HTTP/1.1 302 Found
>    Location: https://client.example.com/cb?error=access_denied&state=xyz

### 4.1.3 访问令牌请求 - Access Token Request

客户端按照附录B中的"application/x-www-form-urlencoded"格式组织如下参数，并使用UTF-8编码后放在HTTP请求体中，发送到token端点：

    grant_type
        必须。值必须为"authorization_code"。

    code
        必须。授权服务器返回的授权码。

    redirect_uri
        必须。如果授权请求中有携带redirect_uri参数，那跟此次的值必须完全一致。

    client_id
        必须，如果客户端如章节3.2.1所述未进行认证。

> The client makes a request to the token endpoint by sending the
>    following parameters using the "application/x-www-form-urlencoded"
>    format per Appendix B with a character encoding of UTF-8 in the HTTP
>    request entity-body:
>
>    grant_type
>          REQUIRED.  Value MUST be set to "authorization_code".
>
>    code
>          REQUIRED.  The authorization code received from the
>          authorization server.
>
>    redirect_uri
>          REQUIRED, if the "redirect_uri" parameter was included in the
>          authorization request as described in Section 4.1.1, and their
>          values MUST be identical.
>
>    client_id
>          REQUIRED, if the client is not authenticating with the
>          authorization server as described in Section 3.2.1.

如果客户端类型是非公开客户端，或者有签发过客户端凭证（或其它认证方式），那客户端必须如章节3.2.1中所述与授权服务器进行认证。

> If the client type is confidential or the client was issued client
>    credentials (or assigned other authentication requirements), the
>    client MUST authenticate with the authorization server as described
>    in Section 3.2.1.

比如，客户端通过TLS发送如下请求：

     POST /token HTTP/1.1
     Host: server.example.com
     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
     Content-Type: application/x-www-form-urlencoded

     grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
     &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

> For example, the client makes the following HTTP request using TLS
>    (with extra line breaks for display purposes only):
>
>      POST /token HTTP/1.1
>      Host: server.example.com
>      Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
>      Content-Type: application/x-www-form-urlencoded
>
>      grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
>      &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

授权服务器必须：

* 要求客户端进行认证（非公开客户端、签发过客户端凭证的客户端以及有其它认证要求的客户端）。

* 如果包含客户端认证信息，则进行认证，

* 确保授权码是签发给当前已认证的非公开客户端，如果客户端类型为公开客户端，则确保授权码是签发给请求中的client_id指定的客户端。

* 验证授权码的有效性，并且：

* 如果授权请求中包含redirect_uri参数，则此处也必须包含，且值必须一致。

> The authorization server MUST:
>
>    o  require client authentication for confidential clients or for any
>       client that was issued client credentials (or with other
>       authentication requirements),
>
>    o  authenticate the client if client authentication is included,
>
>    o  ensure that the authorization code was issued to the authenticated
>       confidential client, or if the client is public, ensure that the
>       code was issued to "client_id" in the request,
>
>    o  verify that the authorization code is valid, and
>
>    o  ensure that the "redirect_uri" parameter is present if the
>       "redirect_uri" parameter was included in the initial authorization
>       request as described in Section 4.1.1, and if included ensure that
>       their values are identical.

4.1.4 访问令牌响应 - Access Token Reponse

如果访问令牌请求是有效且经过客户端认证的，那授权服务器如章节5.1所述返回访问令牌和可选的刷新令牌。如果客户端认证失败，则授权服务器如5.2所述返回错误响应。

> If the access token request is valid and authorized, the
>    authorization server issues an access token and optional refresh
>    token as described in Section 5.1.  If the request client
>    authentication failed or is invalid, the authorization server returns
>    an error response as described in Section 5.2.

如下是成功响应的案例：

     HTTP/1.1 200 OK
     Content-Type: application/json;charset=UTF-8
     Cache-Control: no-store
     Pragma: no-cache

     {
       "access_token":"2YotnFZFEjr1zCsicMWpAA",
       "token_type":"example",
       "expires_in":3600,
       "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
       "example_parameter":"example_value"
     }

> An example successful response:
>
>      HTTP/1.1 200 OK
>      Content-Type: application/json;charset=UTF-8
>      Cache-Control: no-store
>      Pragma: no-cache
>
>      {
>        "access_token":"2YotnFZFEjr1zCsicMWpAA",
>        "token_type":"example",
>        "expires_in":3600,
>        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
>        "example_parameter":"example_value"
>      }

## 4.2 隐式授权模式 - Implicit Grant

隐式授权模式用于获取访问令牌（不支持签发刷新令牌），并且对操作特定重定向URI的公共客户端进行了优化，这类的客户端一般使用类似JavaScript的脚本语言在浏览器上实现。

> The implicit grant type is used to obtain access tokens (it does not
>    support the issuance of refresh tokens) and is optimized for public
>    clients known to operate a particular redirection URI.  These clients
>    are typically implemented in a browser using a scripting language
>    such as JavaScript.

由于该模式依赖重定向，因此客户端必须有能力与资源所有者的user-agent（如web浏览器）进行交互，并且有接收授权服务器请求（通过重定向）的能力。

> Since this is a redirection-based flow, the client must be capable of
>    interacting with the resource owner's user-agent (typically a web
>    browser) and capable of receiving incoming requests (via redirection)
>    from the authorization server.

与授权码模式不同，授权码模式需要通过另个请求来分别获取授权码和访问令牌，而隐式授权模式则是通过授权请求直接获取访问令牌。

> Unlike the authorization code grant type, in which the client makes
>    separate requests for authorization and for an access token, the
>    client receives the access token as the result of the authorization
>    request.

隐式授权模式并不包含客户端认证部分，它依赖资源所有者的认证和注册时的重定向URI。由于访问令牌会在重定向URI中，因此它可能会暴露给资源所有者或在同一设备的其它应用程序。

> The implicit grant type does not include client authentication, and
>    relies on the presence of the resource owner and the registration of
>    the redirection URI.  Because the access token is encoded into the
>    redirection URI, it may be exposed to the resource owner and other
>    applications residing on the same device.

     +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier     +---------------+
     |         -+----(A)-- & Redirection URI --->|               |
     |  User-   |                                | Authorization |
     |  Agent  -|----(B)-- User authenticates -->|     Server    |
     |          |                                |               |
     |          |<---(C)--- Redirection URI ----<|               |
     |          |          with Access Token     +---------------+
     |          |            in Fragment
     |          |                                +---------------+
     |          |----(D)--- Redirection URI ---->|   Web-Hosted  |
     |          |          without Fragment      |     Client    |
     |          |                                |    Resource   |
     |     (F)  |<---(E)------- Script ---------<|               |
     |          |                                +---------------+
     +-|--------+
       |    |
      (A)  (G) Access Token
       |    |
       ^    v
     +---------+
     |         |
     |  Client |
     |         |
     +---------+

图4中包含如下步骤：

    (A) 客户端通过将资源所有者的user-agent重定向到授权端点来初始化授权流程，客户端需要携带客户端标识、请求授权的范围、state以及重定向URI（当授权通过或拒绝时，授权服务器将user-agent重定向回该URI）。

    (B) 授权服务器对资源所有者进行认证，并确认资源所有者是授权还是拒绝客户端的访问请求。

    (C) 假设资源所有者同意授权，那授权服务器将使用之前提供的重定向URI将user-agent重定向回客户端。在重定向URI的fragment部分会包含访问令牌。

    (D) user-agent会遵循重定向指令，向基于web的客户端发起请求（不包含fragment部分 [RFC2616]），frament由user-agent自行处理。

    (E) 基于web的客户端会返回一个web页面（一般是包含内置脚本的HTML文档），该页面有访问包含fragment在内的整个重定向URI的权限，并且会从fragment中获取到访问令牌。

    (F) user-agent执行客户端返回的脚本，用于解析获取访问令牌。

    (G) user-agent将访问令牌传送给客户端。

> The flow illustrated in Figure 4 includes the following steps:
>
>     (A)  The client initiates the flow by directing the resource owner's
>         user-agent to the authorization endpoint.  The client includes
>         its client identifier, requested scope, local state, and a
>         redirection URI to which the authorization server will send the
>         user-agent back once access is granted (or denied).
>
>    (B)  The authorization server authenticates the resource owner (via
>         the user-agent) and establishes whether the resource owner
>         grants or denies the client's access request.
>
>    (C)  Assuming the resource owner grants access, the authorization
>         server redirects the user-agent back to the client using the
>         redirection URI provided earlier.  The redirection URI includes
>         the access token in the URI fragment.
>
>    (D)  The user-agent follows the redirection instructions by making a
>         request to the web-hosted client resource (which does not
>         include the fragment per [RFC2616]).  The user-agent retains the
>         fragment information locally.
>
>    (E)  The web-hosted client resource returns a web page (typically an
>         HTML document with an embedded script) capable of accessing the
>         full redirection URI including the fragment retained by the
>         user-agent, and extracting the access token (and other
>         parameters) contained in the fragment.
>
>    (F)  The user-agent executes the script provided by the web-hosted
>         client resource locally, which extracts the access token.
>
>    (G)  The user-agent passes the access token to the client.

可以从章节1.3.2和9中查阅隐式授权模式的使用背景。
可以从章节10.3和10.16中查阅使用隐式授权模式时需注意的重要安全规约。

> See Sections 1.3.2 and 9 for background on using the implicit grant.
>    See Sections 10.3 and 10.16 for important security considerations
>    when using the implicit grant.

### 4.2.1 授权请求 - Authorization Request

客户端使用附录B中说明的"application/x-www-form-urlencoded"格式，去构造授权端点的请求参数：

    response_type
        必须。值必须为"token"。

    client_id
        必须。章节2.2中描述的客户端标识。

    redirect_uri
        可选。章节3.1.2中有描述。

    scope
        可选。章节3.3中描述的请求访问的范围。

    state
        建议。客户端用来维护请求和回调之间状态的不透明值。授权服务器将user-agent重定向回客户端时会携带该值。该值一般用于防止章节10.12中的跨站请求伪造攻击。

> The client constructs the request URI by adding the following
>    parameters to the query component of the authorization endpoint URI
>    using the "application/x-www-form-urlencoded" format, per Appendix B:
>
>    response_type
>          REQUIRED.  Value MUST be set to "token".
>
>    client_id
>          REQUIRED.  The client identifier as described in Section 2.2.
>
>    redirect_uri
>          OPTIONAL.  As described in Section 3.1.2.
>
>    scope
>          OPTIONAL.  The scope of the access request as described by
>          Section 3.3.
>
>    state
>          RECOMMENDED.  An opaque value used by the client to maintain
>          state between the request and callback.  The authorization
>          server includes this value when redirecting the user-agent back
>          to the client.  The parameter SHOULD be used for preventing
>          cross-site request forgery as described in Section 10.12.

客户端通过HTTP重定向的响应或其它可行的方式，将资源所有者的user-agent引导到构造的URI。

> The client directs the resource owner to the constructed URI using an
>    HTTP redirection response, or by other means available to it via the
>    user-agent.

比如，客户端引导user-agent通过TLS发起如下请求：

    GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
    Host: server.example.com

> For example, the client directs the user-agent to make the following
>    HTTP request using TLS (with extra line breaks for display purposes
>    only):
>
>     GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz
>         &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
>     Host: server.example.com

授权服务器需要校验请求中所有必须的参数是否传入且有效，并且要校验即将用于传递访问令牌的重定向URI，是否与客户端注册时提供的重定向URI完全匹配（如章节3.1.2所述）。

> The authorization server validates the request to ensure that all
>    required parameters are present and valid.  The authorization server
>    MUST verify that the redirection URI to which it will redirect the
>    access token matches a redirection URI registered by the client as
>    described in Section 3.1.2.

如果请求校验通过，授权服务器将引导资源所有者进行授权，并且让其做出授权决策（通过询问资源所有者，或建立其它有效的授权方式）。

> If the request is valid, the authorization server authenticates the
>    resource owner and obtains an authorization decision (by asking the
>    resource owner or by establishing approval via other means).

当用户完成其授权决策后，授权服务器将通过HTTP重定向或其它可行的方式，将user-agent引导到重定向URI。

> When a decision is established, the authorization server directs the
>    user-agent to the provided client redirection URI using an HTTP
>    redirection response, or by other means available to it via the
>    user-agent.

### 4.2.2 访问令牌响应 - Access Token Response

如果资源所有者授权了访问请求，授权服务器需要签发访问令牌，并按照附录B中的约束，将其以"application/x-www-form-urlencoded"的格式添加到重定向URI的查询组件部分：

    access_token
        必须。授权服务器签发的访问令牌。

    token_type
        必须。章节7.1中描述的令牌类型，大小写敏感。

    expires_in
        建议。访问令牌的寿命，以秒为单位。比如，值为"3600"，代表访问令牌将在响应后的一小时后过期。如果忽略该值，则授权服务器比如通过其它方式实践过期时间，或者在文档中明确默认的过期时间。

    scope
        当与请求中列举的范围相同时，则该返回值可选；否则必须返回，且符合章节3.3中的描述。

    state
        当授权请求中包含该字段时，必须原样返回。

> If the resource owner grants the access request, the authorization
>    server issues an access token and delivers it to the client by adding
>    the following parameters to the fragment component of the redirection
>    URI using the "application/x-www-form-urlencoded" format, per
>    Appendix B:
>
>    access_token
>          REQUIRED.  The access token issued by the authorization server.
>
>    token_type
>          REQUIRED.  The type of the token issued as described in
>          Section 7.1.  Value is case insensitive.
>
>    expires_in
>          RECOMMENDED.  The lifetime in seconds of the access token.  For
>          example, the value "3600" denotes that the access token will
>          expire in one hour from the time the response was generated.
>          If omitted, the authorization server SHOULD provide the
>          expiration time via other means or document the default value.
>
>    scope
>          OPTIONAL, if identical to the scope requested by the client;
>          otherwise, REQUIRED.  The scope of the access token as
>          described by Section 3.3.
>
>    state
>          REQUIRED if the "state" parameter was present in the client
>          authorization request.  The exact value received from the
>          client.

授权服务器不得签发刷新令牌。

> The authorization server MUST NOT issue a refresh token.

比如，授权服务器通过如下的HTTP响应对user-agent进行重定向：

    HTTP/1.1 302 Found
    Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
               &state=xyz&token_type=example&expires_in=3600


> For example, the authorization server redirects the user-agent by
>    sending the following HTTP response (with extra line breaks for
>    display purposes only):
>
>      HTTP/1.1 302 Found
>      Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
>                &state=xyz&token_type=example&expires_in=3600

开发者必须注意，某些user-agent并不支持在HTTP的Location头中包含fragment组件，这一类的客户端不能使用3xx重定向响应，而是需要提供其它方式对user-agent进行重定向，比如返回一个包含'continue'按钮的HTML页面，在点击后跳转到重定向URI。

> Developers should note that some user-agents do not support the
>    inclusion of a fragment component in the HTTP "Location" response
>    header field.  Such clients will require using other methods for
>    redirecting the client than a 3xx redirection response -- for
>    example, returning an HTML page that includes a 'continue' button
>    with an action linked to the redirection URI.

客户端必须忽略未定义的响应参数。访问令牌的长度并未在该规范中定义，因此客户端应该避免假设该字段的长度。授权服务器应明确签发的所有值的长度。

> The client MUST ignore unrecognized response parameters.  The access
>    token string size is left undefined by this specification.  The
>    client should avoid making assumptions about value sizes.  The
>    authorization server SHOULD document the size of any value it issues.

#### 4.2.2.1 错误响应- Error Response

如果授权请求由于重定向URI或客户端标识参数存在问题（丢失、无效或不匹配）导致请求失败，授权服务器应该告知资源所有者出现异常，而不是自动将user-agent重定向到无效的重定向URI。

> If the request fails due to a missing, invalid, or mismatching
>    redirection URI, or if the client identifier is missing or invalid,
>    the authorization server SHOULD inform the resource owner of the
>    error and MUST NOT automatically redirect the user-agent to the
>    invalid redirection URI.

如果资源所有者拒绝授权，或出现除丢失、无效重定向URI以外的异常，授权服务器应该通过附录B描述的"application/x-www-form-urlencoded"格式，通过以下参数告知客户端异常原因：

    error
        必须。值为如下简单的ASCII错误码：

        invalid_request
            缺少必须的参数，包含无效的参数值，使用同名参数，以及其它问题。

        unauthorized_client
            客户端没有使用该方法获取访问令牌的权限。

        access_denied
            资源所有者拒绝授权。

        unsupported_response_type
            授权服务器不支持通过该方法获取访问令牌。

        invalid_scope
            请求的授权范围无效或未定义。

        server_error
            授权服务器发生意外情况，无法完成请求（之所以需要该错误代码，是因为无法通过HTTP重定向将500内部服务器错误状态返回给客户端）。

        temporarily_unavailable
            由于服务器临时过载或维护，授权服务器当前无法处理该请求（之所以需要该错误代码，是因为无法通过HTTP重定向将503服务器不可用状态返回给客户端）。

        error参数值包含的字符必须在%x20-21 / %x23-5B / %x5D-7E范围内。

    error_description
        可选。可理解的ASCII文本，用于提供额外的信息，帮助客户端开发者理解发生了何种异常。
        error_description参数值包含的字符必须在%x20-21 / %x23-5B / %x5D-7E范围内。
    
    error_uri
        可选。包含错误信息的web界面的URI，用于向客户端开发人员提供额外的错误信息。
        error_uri参数值必须符合URI-reference语法，并且包含的字符必须在%x21 / %x23-5B / %x5D-7E范围内。

    state
        如果客户端在授权请求中携带该参数，则必须原样返回。

> If the resource owner denies the access request or if the request
>    fails for reasons other than a missing or invalid redirection URI,
>    the authorization server informs the client by adding the following
>    parameters to the fragment component of the redirection URI using the
>    "application/x-www-form-urlencoded" format, per Appendix B:
>
>    error
>          REQUIRED.  A single ASCII [USASCII] error code from the
>          following:
>
>          invalid_request
>                The request is missing a required parameter, includes an
>                invalid parameter value, includes a parameter more than
>                once, or is otherwise malformed.
>
>          unauthorized_client
>                The client is not authorized to request an access token
>                using this method.
>
>          access_denied
>                The resource owner or authorization server denied the
>                request.
>
>          unsupported_response_type
>                The authorization server does not support obtaining an
>                access token using this method.
>
>          invalid_scope
>                The requested scope is invalid, unknown, or malformed.
>
>          server_error
>                The authorization server encountered an unexpected
>                condition that prevented it from fulfilling the request.
>                (This error code is needed because a 500 Internal Server
>                Error HTTP status code cannot be returned to the client
>                via an HTTP redirect.)
>
>          temporarily_unavailable
>                The authorization server is currently unable to handle
>                the request due to a temporary overloading or maintenance
>                of the server.  (This error code is needed because a 503
>                Service Unavailable HTTP status code cannot be returned
>                to the client via an HTTP redirect.)
>
>          Values for the "error" parameter MUST NOT include characters
>          outside the set %x20-21 / %x23-5B / %x5D-7E.
>
>    error_description
>          OPTIONAL.  Human-readable ASCII [USASCII] text providing
>          additional information, used to assist the client developer in
>          understanding the error that occurred.
>          Values for the "error_description" parameter MUST NOT include
>          characters outside the set %x20-21 / %x23-5B / %x5D-7E.
>
>    error_uri
>          OPTIONAL.  A URI identifying a human-readable web page with
>          information about the error, used to provide the client
>          developer with additional information about the error.
>          Values for the "error_uri" parameter MUST conform to the
>          URI-reference syntax and thus MUST NOT include characters
>          outside the set %x21 / %x23-5B / %x5D-7E.
>
>    state
>          REQUIRED if a "state" parameter was present in the client
>          authorization request.  The exact value received from the
>          client.

比如，授权服务器通过如下HTTP响应对user-agent进行重定向：

    HTTP/1.1 302 Found
    Location: https://client.example.com/cb#error=access_denied&state=xyz

> For example, the authorization server redirects the user-agent by
>    sending the following HTTP response:
>
>    HTTP/1.1 302 Found
>    Location: https://client.example.com/cb#error=access_denied&state=xyz

## 4.3 资源所有者密码凭证模式 - Resource Owner Password Credentials Grant

资源所有者密码模式，适用于当资源所有者与客户端具有良好信任关系的场景，比如客户端是设备的操作系统或具备高权限的应用。授权服务器在开放此种授权模式时必须格外小心，并且只有在别的模式不可用时才允许这种模式。

> The resource owner password credentials grant type is suitable in
>    cases where the resource owner has a trust relationship with the
>    client, such as the device operating system or a highly privileged
>    application.  The authorization server should take special care when
>    enabling this grant type and only allow it when other flows are not
>    viable.

该模式适用于客户端有能力获取资源所有者的凭证（用户名密码，典型的通过交互式表单来获取）的场景，同时，也适用于现存的通过HTTP Basic或Digest模式进行认证的客户端，想迁移到OAuth的场景（通过已存储的资源所有者的凭证来换取访问令牌）。

> This grant type is suitable for clients capable of obtaining the
>    resource owner's credentials (username and password, typically using
>    an interactive form).  It is also used to migrate existing clients
>    using direct authentication schemes such as HTTP Basic or Digest
>    authentication to OAuth by converting the stored credentials to an
>    access token.

     +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          v
          |    Resource Owner
         (A) Password Credentials
          |
          v
     +---------+                                  +---------------+
     |         |>--(B)---- Resource Owner ------->|               |
     |         |         Password Credentials     | Authorization |
     | Client  |                                  |     Server    |
     |         |<--(C)---- Access Token ---------<|               |
     |         |    (w/ Optional Refresh Token)   |               |
     +---------+                                  +---------------+

图5中包含如下步骤：

    (A) 资源所有者向客户端提供自己的用户名和密码。

    (B) 客户端通过使用资源所有者的用户名和密码来访问授权服务器的令牌端点，以获取访问令牌。当发起该请求时，授权服务器需要认证客户端的身份。

    (C) 授权服务器验证客户端身份，同时也验证资源所有者的凭据，如果都通过，则签发访问令牌。

> The flow illustrated in Figure 5 includes the following steps:
>
>    (A)  The resource owner provides the client with its username and
>         password.
>
>    (B)  The client requests an access token from the authorization
>         server's token endpoint by including the credentials received
>         from the resource owner.  When making the request, the client
>         authenticates with the authorization server.
>
>    (C)  The authorization server authenticates the client and validates
>         the resource owner credentials, and if valid, issues an access
>         token.

### 4.3.1 授权请求及响应 - Authorization Request and Response

客户端如何获取资源所有者的凭据超出了本规范的讨论范围。当客户端已经获取到访问令牌后，需要丢弃资源所有者的原始凭证。

> The method through which the client obtains the resource owner
>    credentials is beyond the scope of this specification.  The client
>    MUST discard the credentials once an access token has been obtained.

### 4.3.2 访问令牌请求 - Access Token Request

客户端需要如附录B中的描述，将如下参数按照"application/x-www-form-urlencoded"进行拼装，并以UTF-8进行编码，放置在HTTP的请求体中，来访问令牌端点：

    grant_type
        必须。值为"password"。

    username
        必须。资源所有者的用户名。

    password
        必须。资源所有者的密码。

    scope
        可选。如章节3.3中描述的请求范围。

> The client makes a request to the token endpoint by adding the
>    following parameters using the "application/x-www-form-urlencoded"
>    format per Appendix B with a character encoding of UTF-8 in the HTTP
>    request entity-body:
>
>    grant_type
>          REQUIRED.  Value MUST be set to "password".
>
>    username
>          REQUIRED.  The resource owner username.
>
>    password
>          REQUIRED.  The resource owner password.
>
>    scope
>          OPTIONAL.  The scope of the access request as described by
>          Section 3.3.

如果客户端类型为非公开客户端，或者签发过客户端凭证（或需要满足其它的认证要求），那授权服务器需要如3.2.1中描述，对客户端进行验证。

> If the client type is confidential or the client was issued client
>    credentials (or assigned other authentication requirements), the
>    client MUST authenticate with the authorization server as described
>    in Section 3.2.1.

比如，客户端通过TLS发起如下HTTP请求：

    POST /token HTTP/1.1
    Host: server.example.com
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    Content-Type: application/x-www-form-urlencoded

    grant_type=password&username=johndoe&password=A3ddj3w

> For example, the client makes the following HTTP request using
>    transport-layer security (with extra line breaks for display purposes
>    only):
>
>      POST /token HTTP/1.1
>      Host: server.example.com
>      Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
>      Content-Type: application/x-www-form-urlencoded
>
>      grant_type=password&username=johndoe&password=A3ddj3w

授权服务器必须：

* 要求非公开客户端或签发了客户端凭据的客户端进行认证。

* 对需要认证的客户端进行认证。

* 通过已有的密码处理算法，验证资源所有者的密码凭据。

> The authorization server MUST:
>
>    o  require client authentication for confidential clients or for any
>       client that was issued client credentials (or with other
>       authentication requirements),
>
>    o  authenticate the client if client authentication is included, and
>
>    o  validate the resource owner password credentials using its
>       existing password validation algorithm.

由于token请求涉及资源所有者的密码，因此授权服务器需要保护其免受暴力破解攻击。

> Since this access token request utilizes the resource owner's
>    password, the authorization server MUST protect the endpoint against
>    brute force attacks (e.g., using rate-limitation or generating
>    alerts).

### 4.3.3 访问令牌响应 - Access Token Response

如果访问令牌请求有效且授权通过，则授权服务器按5.1的描述签发访问令牌和可选的刷新令牌。如果无效或授权失败，则按5.2的描述返回适当的错误信息。

> If the access token request is valid and authorized, the
>    authorization server issues an access token and optional refresh
>    token as described in Section 5.1.  If the request failed client
>    authentication or is invalid, the authorization server returns an
>    error response as described in Section 5.2.

成功的响应案例如下：

    HTTP/1.1 200 OK
    Content-Type: application/json;charset=UTF-8
    Cache-Control: no-store
    Pragma: no-cache

    {
      "access_token":"2YotnFZFEjr1zCsicMWpAA",
      "token_type":"example",
      "expires_in":3600,
      "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
      "example_parameter":"example_value"
    }

> An example successful response:
>
>      HTTP/1.1 200 OK
>      Content-Type: application/json;charset=UTF-8
>      Cache-Control: no-store
>      Pragma: no-cache
>
>      {
>        "access_token":"2YotnFZFEjr1zCsicMWpAA",
>        "token_type":"example",
>        "expires_in":3600,
>        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
>        "example_parameter":"example_value"
>      }

## 4.4 客户端凭证模式 - Client Credentials Grant

客户端可以仅通过客户端凭证（或其它受支持的认证方式）来请求访问令牌，用于访问其可控范围内的受保护资源，此外，也可以访问跟其他的与授权服务器提前协商好的资源所有者的受保护资源（超出本规范的讨论范围）。

> The client can request an access token using only its client
>    credentials (or other supported means of authentication) when the
>    client is requesting access to the protected resources under its
>    control, or those of another resource owner that have been previously
>    arranged with the authorization server (the method of which is beyond
>    the scope of this specification).

只有非公开客户端，才能使用客户端凭证授权方式。

> The client credentials grant type MUST only be used by confidential
>    clients.

     +---------+                                  +---------------+
     |         |                                  |               |
     |         |>--(A)- Client Authentication --->| Authorization |
     | Client  |                                  |     Server    |
     |         |<--(B)---- Access Token ---------<|               |
     |         |                                  |               |
     +---------+                                  +---------------+

图6包含如下步骤：

    (A) 客户端向授权服务器发起认证并请求获取访问令牌。

    (B) 授权服务器验证客户端身份，如果通过，则签发访问令牌。

> The flow illustrated in Figure 6 includes the following steps:
>
>    (A)  The client authenticates with the authorization server and
>         requests an access token from the token endpoint.
>
>    (B)  The authorization server authenticates the client, and if valid,
>         issues an access token.

### 4.4.1 授权请求和响应 - Autorization Request and Response

使用客户端凭证模式时，不需要发起授权请求。

> Since the client authentication is used as the authorization grant,
>    no additional authorization request is needed.

###  4.4.2 访问令牌请求

客户端需要如附录B中的描述，将如下参数按照"application/x-www-form-urlencoded"进行拼装，并以UTF-8进行编码，放置在HTTP的请求体中，来访问令牌端点：

    grant_type
        必须。值为"client_credentials"。
    
    scope
        可选。如章节3.3所述的请求范围。

> The client makes a request to the token endpoint by adding the
>    following parameters using the "application/x-www-form-urlencoded"
>    format per Appendix B with a character encoding of UTF-8 in the HTTP
>    request entity-body:
>
>    grant_type
>          REQUIRED.  Value MUST be set to "client_credentials".
>
>    scope
>          OPTIONAL.  The scope of the access request as described by
>          Section 3.3.

客户端需要如章节3.2.1所述进行客户端认证。

> The client MUST authenticate with the authorization server as
>    described in Section 3.2.1.

比如，客户端通过TLS发起如下的HTTP请求：

    POST /token HTTP/1.1
    Host: server.example.com
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    Content-Type: application/x-www-form-urlencoded

    grant_type=client_credentials

> For example, the client makes the following HTTP request using
>   transport-layer security (with extra line breaks for display purposes
>   only):
>
>     POST /token HTTP/1.1
>     Host: server.example.com
>     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
>     Content-Type: application/x-www-form-urlencoded
>
>     grant_type=client_credentials

授权服务器必须对客户端进行认证。

> The authorization server MUST authenticate the client.

### 4.4.3 访问令牌响应

如果访问令牌请求有效且授权通过，则授权服务器按照5.1所述签发访问令牌（不得签发刷新令牌）。如果请求无效或授权失败，则如5.2所述返回错误响应。

> If the access token request is valid and authorized, the
>    authorization server issues an access token as described in
>    Section 5.1.  A refresh token SHOULD NOT be included.  If the request
>    failed client authentication or is invalid, the authorization server
>    returns an error response as described in Section 5.2.


## 4.5 扩展授权模式 - Extension Grants

客户端通过将令牌端点的grant_type参数声明为一个URI（由授权服务器定义）来使用扩展模式，同时可以增加一些必要的可选参数。

> The client uses an extension grant type by specifying the grant type
>    using an absolute URI (defined by the authorization server) as the
>    value of the "grant_type" parameter of the token endpoint, and by
>    adding any additional parameters necessary.

比如，通过使用[OAuth-SAML2]定义的SAML2.0来获取访问令牌，客户端会用TLS链路发起如下HTTP请求：

    POST /token HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-
    bearer&assertion=PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU
    [...omitted for brevity...]aG5TdGF0ZW1lbnQ-PC9Bc3NlcnRpb24-

> For example, to request an access token using a Security Assertion
>    Markup Language (SAML) 2.0 assertion grant type as defined by
>    [OAuth-SAML2], the client could make the following HTTP request using
>    TLS (with extra line breaks for display purposes only):
>
>      POST /token HTTP/1.1
>      Host: server.example.com
>      Content-Type: application/x-www-form-urlencoded
>
>      grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-
>      bearer&assertion=PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU
>      [...omitted for brevity...]aG5TdGF0ZW1lbnQ-PC9Bc3NlcnRpb24-

如果访问令牌请求有效且授权通过，则授权服务器按5.1的描述签发访问令牌和可选的刷新令牌。如果无效或授权失败，则按5.2的描述返回适当的错误信息。

> If the access token request is valid and authorized, the
>    authorization server issues an access token and optional refresh
>    token as described in Section 5.1.  If the request failed client
>    authentication or is invalid, the authorization server returns an
>    error response as described in Section 5.2.


# 5. 签发访问令牌 - Issuing an Access Token

如果访问令牌请求有效且授权通过，则授权服务器按5.1的描述签发访问令牌和可选的刷新令牌。如果无效或授权失败，则按5.2的描述返回适当的错误信息。

> If the access token request is valid and authorized, the
>    authorization server issues an access token and optional refresh
>    token as described in Section 5.1.  If the request failed client
>    authentication or is invalid, the authorization server returns an
>    error response as described in Section 5.2.

## 5.1 成功响应 - Successful Response

授权服务器签发访问令牌和可选的刷新令牌，其响应结构是将如下参数组织到HTTP响应的消息体中，并返回200响应码：

    access_token
        必须。授权服务器签发的访问令牌。

    token_type
        必须。如章节7.1所述，标识签发的令牌的类型，大小写敏感。

    expires_in
        建议。访问令牌的寿命，以秒为单位。比如，值为"3600"，代表访问令牌将在响应后的一小时后过期。如果忽略该值，则授权服务器比如通过其它方式实践过期时间，或者在文档中明确默认的过期时间。
    
    refresh_token
        可选。刷新令牌，使用章节6中描述的授权方式来获取新的访问令牌。

    scope
        当与请求中列举的范围相同时，则该返回值可选；否则必须返回，且符合章节3.3中的描述。

> The authorization server issues an access token and optional refresh
>    token, and constructs the response by adding the following parameters
>    to the entity-body of the HTTP response with a 200 (OK) status code:
>
>    access_token
>          REQUIRED.  The access token issued by the authorization server.
>
>    token_type
>          REQUIRED.  The type of the token issued as described in
>          Section 7.1.  Value is case insensitive.
>
>    expires_in
>          RECOMMENDED.  The lifetime in seconds of the access token.  For
>          example, the value "3600" denotes that the access token will
>          expire in one hour from the time the response was generated.
>          If omitted, the authorization server SHOULD provide the
>          expiration time via other means or document the default value.
>
>    refresh_token
>          OPTIONAL.  The refresh token, which can be used to obtain new
>          access tokens using the same authorization grant as described
>          in Section 6.
>
>    scope
>          OPTIONAL, if identical to the scope requested by the client;
>          otherwise, REQUIRED.  The scope of the access token as
>          described by Section 3.3.

参数应如[RFC4627]中所描述的，使用"application/json"媒体类型，并置于HTTP响应的响应体中。这些参数会被序列化为JSON格式，如上的参数都置于JSON的顶级。参数名和参数值都作为JSON字符串，数值类型的参数值作为JSON数字。这些参数排列的顺序无关。

> The parameters are included in the entity-body of the HTTP response
>    using the "application/json" media type as defined by [RFC4627].  The
>    parameters are serialized into a JavaScript Object Notation (JSON)
>    structure by adding each parameter at the highest structure level.
>    Parameter names and string values are included as JSON strings.
>    Numerical values are included as JSON numbers.  The order of
>    parameters does not matter and can vary.

授权服务器必须包含"Cache-Control"响应头，对所有包含令牌、凭证和其它敏感信息的响应，都需要将其值设置为"no-store"，同样的，"Pragma"响应头也要设置为"no-cache"。

> The authorization server MUST include the HTTP "Cache-Control"
>    response header field [RFC2616] with a value of "no-store" in any
>    response containing tokens, credentials, or other sensitive
>    information, as well as the "Pragma" response header field [RFC2616]
>    with a value of "no-cache".

举例如下：

    HTTP/1.1 200 OK
    Content-Type: application/json;charset=UTF-8
    Cache-Control: no-store
    Pragma: no-cache

    {
      "access_token":"2YotnFZFEjr1zCsicMWpAA",
      "token_type":"example",
      "expires_in":3600,
      "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
      "example_parameter":"example_value"
    }

> For example:
>
>      HTTP/1.1 200 OK
>      Content-Type: application/json;charset=UTF-8
>      Cache-Control: no-store
>      Pragma: no-cache
>
>      {
>        "access_token":"2YotnFZFEjr1zCsicMWpAA",
>        "token_type":"example",
>        "expires_in":3600,
>        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
>        "example_parameter":"example_value"
>      }

客户端必须忽略未定义的响应参数。访问令牌和其它值的长度并未在该规范中定义，因此客户端应该避免假设这些字段的长度。授权服务器应明确自己签发的所有值的长度。

> The client MUST ignore unrecognized value names in the response.  The
>    sizes of tokens and other values received from the authorization
>    server are left undefined.  The client should avoid making
>    assumptions about value sizes.  The authorization server SHOULD
>    document the size of any value it issues.

## 5.2 错误响应 - Error Response

授权服务器返回400（Bad Request）响应码（除非另有声明）以及如下响应参数：

    error
        必须。值为如下简单的ASCII错误码：

        invalid_request
            请求丢失必要的参数，或包含不支持的参数（超出授权类型规约的），或使用重复的参数，或包含多种凭证，或使用多种机制进行客户端认证，以及其它的问题。
        
        invalid_client
            客户端认证失败（如，未知的客户端、没有包含客户端认证信息、不支持的认证方式等）。授权服务器可能返回401响应码来指明支持何种类型的HTTP认证方式。如果客户端希望通过Authorization请求头进行认证，那授权服务器必须返回401响应，并包含WWW-Autoenticate响应头来指明客户端使用的认证方式。

        invalid_grant
            采用的授权方式或刷新令牌是无效的、过期的、已吊销的、重定向URI不匹配以及是签发给其它客户端的等等。

        unauthorized_client
            已认证的客户端没有使用此种授权模式的权限。

        unsupported_grant_type
            授权服务器不支持此种授权模式。

        invalid_scope
            请求的授权范围是无效的、未知的，或超出资源所有者的授权范围。

        error参数值包含的字符必须在%x20-21 / %x23-5B / %x5D-7E范围内。

    error_description
        可选。可理解的ASCII文本，用于提供额外的信息，帮助客户端开发者理解发生了何种异常。
        error_description参数值包含的字符必须在%x20-21 / %x23-5B / %x5D-7E范围内。
    
    error_uri
        可选。包含错误信息的web界面的URI，用于向客户端开发人员提供额外的错误信息。
        error_uri参数值必须符合URI-reference语法，并且包含的字符必须在%x21 / %x23-5B / %x5D-7E范围内。

> The authorization server responds with an HTTP 400 (Bad Request)
>    status code (unless specified otherwise) and includes the following
>    parameters with the response:
>
>    error
>          REQUIRED.  A single ASCII [USASCII] error code from the
>          following:
>
>          invalid_request
>                The request is missing a required parameter, includes an
>                unsupported parameter value (other than grant type),
>                repeats a parameter, includes multiple credentials,
>                utilizes more than one mechanism for authenticating the
>                client, or is otherwise malformed.
>
>          invalid_client
>                Client authentication failed (e.g., unknown client, no
>                client authentication included, or unsupported
>                authentication method).  The authorization server MAY
>                return an HTTP 401 (Unauthorized) status code to indicate
>                which HTTP authentication schemes are supported.  If the
>                client attempted to authenticate via the "Authorization"
>                request header field, the authorization server MUST
>                respond with an HTTP 401 (Unauthorized) status code and
>                include the "WWW-Authenticate" response header field
>                matching the authentication scheme used by the client.
>
>          invalid_grant
>                The provided authorization grant (e.g., authorization
>                code, resource owner credentials) or refresh token is
>                invalid, expired, revoked, does not match the redirection
>                URI used in the authorization request, or was issued to
>                another client.
>
>          unauthorized_client
>                The authenticated client is not authorized to use this
>                authorization grant type.
>
>          unsupported_grant_type
>                The authorization grant type is not supported by the
>                authorization server.
>
>          invalid_scope
>                The requested scope is invalid, unknown, malformed, or
>                exceeds the scope granted by the resource owner.
>
>          Values for the "error" parameter MUST NOT include characters
>          outside the set %x20-21 / %x23-5B / %x5D-7E.
>
>    error_description
>          OPTIONAL.  Human-readable ASCII [USASCII] text providing
>          additional information, used to assist the client developer in
>          understanding the error that occurred.
>          Values for the "error_description" parameter MUST NOT include
>          characters outside the set %x20-21 / %x23-5B / %x5D-7E.
>
>    error_uri
>          OPTIONAL.  A URI identifying a human-readable web page with
>          information about the error, used to provide the client
>          developer with additional information about the error.
>          Values for the "error_uri" parameter MUST conform to the
>          URI-reference syntax and thus MUST NOT include characters
>          outside the set %x21 / %x23-5B / %x5D-7E.

参数应如[RFC4627]中所描述的，使用"application/json"媒体类型，并置于HTTP响应的响应体中。这些参数会被序列化为JSON格式，如上的参数都置于JSON的顶级。参数名和参数值都作为JSON字符串，数值类型的参数值作为JSON数字。这些参数排列的顺序无关。

> The parameters are included in the entity-body of the HTTP response
>    using the "application/json" media type as defined by [RFC4627].  The
>    parameters are serialized into a JSON structure by adding each
>    parameter at the highest structure level.  Parameter names and string
>    values are included as JSON strings.  Numerical values are included
>    as JSON numbers.  The order of parameters does not matter and can
>    vary.

举例如下：

    HTTP/1.1 400 Bad Request
    Content-Type: application/json;charset=UTF-8
    Cache-Control: no-store
    Pragma: no-cache

    {
      "error":"invalid_request"
    }

> For example:
>
>      HTTP/1.1 400 Bad Request
>      Content-Type: application/json;charset=UTF-8
>      Cache-Control: no-store
>      Pragma: no-cache
>
>      {
>        "error":"invalid_request"
>      }


# 访问令牌的刷新 - Refreshing an Access Token

如果授权服务器有签发刷新令牌给客户端，那客户端可以如附录B中的描述通过"application/x-www-form-urlencoded"格式组织如下参数，并使用UTF-8进行编码后放入HTTP请求体。将请求发送至token端点以刷新访问令牌：

    grant_type
        必须。值必须为"refresh_token"。

    refresh_token
        必须。签发给客户端的刷新令牌。

    scope
        可选。章节3.3中描述的请求授权的范围，scope的值不能包括最初资源所有者未授权的值，如果忽略该参数，则视为与资源所有者最初授权的值相同。

> If the authorization server issued a refresh token to the client, the
>    client makes a refresh request to the token endpoint by adding the
>    following parameters using the "application/x-www-form-urlencoded"
>    format per Appendix B with a character encoding of UTF-8 in the HTTP
>    request entity-body:
>
>    grant_type
>          REQUIRED.  Value MUST be set to "refresh_token".
>
>    refresh_token
>          REQUIRED.  The refresh token issued to the client.
>
>    scope
>          OPTIONAL.  The scope of the access request as described by
>          Section 3.3.  The requested scope MUST NOT include any scope
>          not originally granted by the resource owner, and if omitted is
>          treated as equal to the scope originally granted by the
>          resource owner.

由于刷新令牌是用于请求额外访问令牌的长时效令牌，因此刷新令牌需要跟客户端做绑定。如果客户端类型是非公开客户端或者签发过客户端凭证（或其它认证方式），则授权服务器必须如章节3.2.1所述对客户端身份进行校验。

> Because refresh tokens are typically long-lasting credentials used to
>   request additional access tokens, the refresh token is bound to the
>   client to which it was issued.  If the client type is confidential or
>   the client was issued client credentials (or assigned other
>   authentication requirements), the client MUST authenticate with the
>   authorization server as described in Section 3.2.1.

比如，客户端通过TLS发起如下HTTP请求：

    POST /token HTTP/1.1
    Host: server.example.com
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA


> For example, the client makes the following HTTP request using
>   transport-layer security (with extra line breaks for display purposes
>   only):
>
>     POST /token HTTP/1.1
>     Host: server.example.com
>     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
>     Content-Type: application/x-www-form-urlencoded
>
>     grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA

授权服务器必须：

* 验证非公开客户端或其它签发过客户端凭证（或其它认证方式）的客户端的身份。

* 若包含客户端认证信息，则进行校验，并且确保刷新令牌是签发给当前认证过的客户端，并且

* 验证刷新令牌的有效性。

> The authorization server MUST:
>
>    o  require client authentication for confidential clients or for any
>       client that was issued client credentials (or with other
>       authentication requirements),
>
>    o  authenticate the client if client authentication is included and
>       ensure that the refresh token was issued to the authenticated
>       client, and
>
>    o  validate the refresh token.

如果验证且授权通过，则授权服务器按5.1所述签发访问令牌，如果验证失败或无效，则如5.2所述返回错误响应。

> If valid and authorized, the authorization server issues an access
>    token as described in Section 5.1.  If the request failed
>    verification or is invalid, the authorization server returns an error
>    response as described in Section 5.2.

授权服务器可能会签发一个新的访问令牌，这时客户端需要丢弃原有的刷新令牌并用新的替换它，授权服务器在签发新的刷新令牌后，可能会吊销掉老的刷新令牌。如果签发新的刷新令牌，那该刷新令牌的授权范围必须与请求中携带的刷新令牌保持一致。

> The authorization server MAY issue a new refresh token, in which case
>    the client MUST discard the old refresh token and replace it with the
>    new refresh token.  The authorization server MAY revoke the old
>    refresh token after issuing a new refresh token to the client.  If a
>    new refresh token is issued, the refresh token scope MUST be
>    identical to that of the refresh token included by the client in the
>    request.

# 7. 访问受保护资源 - Accessing Protected Resources

客户端通过向资源服务器出示访问令牌来访问受保护资源。资源服务器必须检验该访问令牌，确保其未过期，且授权的scope可以访问当前请求的资源。资源服务器如何校验访问令牌超出了本规范要讨论的范围，但一般是通过与授权服务器之间进行交互协作来实现。

> The client accesses protected resources by presenting the access
>    token to the resource server.  The resource server MUST validate the
>    access token and ensure that it has not expired and that its scope
>    covers the requested resource.  The methods used by the resource
>    server to validate the access token (as well as any error responses)
>    are beyond the scope of this specification but generally involve an
>    interaction or coordination between the resource server and the
>    authorization server.

客户端如何使用访问令牌与资源服务器进行认证，取决于授权服务器签发的访问令牌的类型。一般来说，会使用[RFC2617]中提及的HTTP的"Authorization"请求头，配合所使用的访问令牌类型的相关规范文档中定义的认证方案来协调实现，如[RFC6750]。

> The method in which the client utilizes the access token to
>    authenticate with the resource server depends on the type of access
>    token issued by the authorization server.  Typically, it involves
>    using the HTTP "Authorization" request header field [RFC2617] with an
>    authentication scheme defined by the specification of the access
>    token type used, such as [RFC6750].

## 7.1 访问令牌类型 - Access Token Types

访问令牌的类型能告知客户端如何成功使用访问令牌访问受保护资源，如果客户端不清楚访问令牌的类型，则不得使用该访问令牌。

> The access token type provides the client with the information
>    required to successfully utilize the access token to make a protected
>    resource request (along with type-specific attributes).  The client
>    MUST NOT use an access token if it does not understand the token
>    type.

比如，[RFC6750]中定义的bearer令牌类型，通过简单的将访问令牌包含到如下请求中进行使用：

    GET /resource/1 HTTP/1.1
    Host: example.com
    Authorization: Bearer mF_9.B5f-4.1JqM

> For example, the "bearer" token type defined in [RFC6750] is utilized
>    by simply including the access token string in the request:
>
>      GET /resource/1 HTTP/1.1
>      Host: example.com
>      Authorization: Bearer mF_9.B5f-4.1JqM

当使用[OAuth-HTTP-MAC]中定义的mac令牌类型时，通过对HTTP请求中的主要组件进行签名（消息认证码），来与访问令牌配合使用：

    GET /resource/1 HTTP/1.1
    Host: example.com
    Authorization: MAC id="h480djs93hd8",
                        nonce="274312:dj83hs9s",
                        mac="kDZvddkndxvhGRXZhvuDjEWhGeE="

> while the "mac" token type defined in [OAuth-HTTP-MAC] is utilized by
>    issuing a Message Authentication Code (MAC) key together with the
>    access token that is used to sign certain components of the HTTP
>    requests:
>
>      GET /resource/1 HTTP/1.1
>      Host: example.com
>      Authorization: MAC id="h480djs93hd8",
>                         nonce="274312:dj83hs9s",
>                         mac="kDZvddkndxvhGRXZhvuDjEWhGeE="

如上的仅作为示例，开发者在实际使用前，请参考[RFC6750]and[OAuth-HTTP-MAC]规范。

> The above examples are provided for illustration purposes only.
>    Developers are advised to consult the [RFC6750] and [OAuth-HTTP-MAC]
>    specifications before use.

所有访问令牌类型的声明，都必须说明与access_token配合使用的额外的参数（如果有）。它同时也定义当访问受保护资源时，应该采用何种HTTP认证方式来携带访问令牌。

> Each access token type definition specifies the additional attributes
>    (if any) sent to the client together with the "access_token" response
>    parameter.  It also defines the HTTP authentication method used to
>    include the access token when making a protected resource request.

## 7.2 错误响应 - Error Response

如果资源访问失败，资源服务器应该告知客户端错误原因。这类错误的细节信息不在本规范的讨论范围内，但本文档在11.4章节还是为OAuth令牌认证方案的错误值建立了一个共享的注册表。

> If a resource access request fails, the resource server SHOULD inform
>    the client of the error.  While the specifics of such error responses
>    are beyond the scope of this specification, this document establishes
>    a common registry in Section 11.4 for error values to be shared among
>    OAuth token authentication schemes.

如果新的认证方案主要是为OAuth令牌认证方案设计的，那么应该定义一种向客户端提供错误状态码的机制，在该机制中，错误码应注册在本规范建立的共享注册表中。

> New authentication schemes designed primarily for OAuth token
>    authentication SHOULD define a mechanism for providing an error
>    status code to the client, in which the error values allowed are
>    registered in the error registry established by this specification.

这类方案可以将有效的错误状态码设置为已注册项的子集。如果使用命名参数来返回错误码，参数名应该为error。

> Such schemes MAY limit the set of valid error codes to a subset of
>    the registered values.  If the error code is returned using a named
>    parameter, the parameter name SHOULD be "error".

如果认证方案有能力作为OAuth令牌认证方案，但主要不是为此设计的，也可以用同样的方式将自己的错误码绑定到注册表中。

> Other schemes capable of being used for OAuth token authentication,
>    but not primarily designed for that purpose, MAY bind their error
>    values to the registry in the same manner.

新的认证方案也可以选择使用error_description和error_uri参数，以与本规范中error参数平行的方式返回错误信息。

> New authentication schemes MAY choose to also specify the use of the
>    "error_description" and "error_uri" parameters to return error
>    information in a manner parallel to their usage in this
>    specification.

# 8. 扩展点 - Extensibility

## 8.1 定义访问令牌类型 - Defining Access Token Types

访问令牌类型可以以如下两种方式定义：
* 注册到访问令牌类型注册表（按照章节11.1中的流程）；
* 使用代表其名称的绝对路径URI；

> Access token types can be defined in one of two ways: registered in
>    the Access Token Types registry (following the procedures in
>    Section 11.1), or by using a unique absolute URI as its name.

使用URI名称的令牌类型，应限制为特定的供应商的实现，这些实现通常是不通用的，且仅特定于使用它们的资源服务器。

> Types utilizing a URI name SHOULD be limited to vendor-specific
>    implementations that are not commonly applicable, and are specific to
>    the implementation details of the resource server where they are
>    used.

其余的令牌类型都应该注册到注册表。类型名称必须遵循type-name范式，如果该类型定义包含HTTP认证方案，则类型名称必须与HTTP认证方案相同（如[RFC2617]所定义），"example"这种类型作为示例中的保留类型。

    type-name  = 1*name-char
    name-char  = "-" / "." / "_" / DIGIT / ALPHA

> All other types MUST be registered.  Type names MUST conform to the
>    type-name ABNF.  If the type definition includes a new HTTP
>    authentication scheme, the type name SHOULD be identical to the HTTP
>    authentication scheme name (as defined by [RFC2617]).  The token type
>    "example" is reserved for use in examples.
>
>      type-name  = 1*name-char
>      name-char  = "-" / "." / "_" / DIGIT / ALPHA

## 8.2 定义新的端点的参数 - Defining New Endpoint Parameters

在授权或令牌端点使用新的请求或响应参数，需要遵循章节11.2中的流程，在OAuth Parameters注册表中定义和注册。

> New request or response parameters for use with the authorization
>    endpoint or the token endpoint are defined and registered in the
>    OAuth Parameters registry following the procedure in Section 11.2.

参数名必须遵循param-name范式，并且参数值的语法也需要被明确定义（比如，使用ABNF，或者指向已存在参数的语法的引用）。

> Parameter names MUST conform to the param-name ABNF, and parameter
>    values syntax MUST be well-defined (e.g., using ABNF, or a reference
>    to the syntax of an existing parameter).
>
>      param-name  = 1*name-char
>      name-char   = "-" / "." / "_" / DIGIT / ALPHA

未注册的、限制于供应商的参数扩展通常不具备适用性，并且受限于使用他们的授权服务器。这些参数通常可以加多一个命名前缀，以避免与其它注册值冲突（比如，使用'companyname_'前缀）。

> Unregistered vendor-specific parameter extensions that are not
>    commonly applicable and that are specific to the implementation
>    details of the authorization server where they are used SHOULD
>    utilize a vendor-specific prefix that is not likely to conflict with
>    other registered values (e.g., begin with 'companyname_').

## 8.3 定义新的授权流程 - Defining New Authorization Grant Types

可以通过为grant_type参数指定唯一的绝对URI路径，来定义新的授权流程。如果这个扩展的授权类型需要在令牌端点使用额外的参数，那必须如章节11.2所述，在OAuth Parameters注册表中进行注册。

> New authorization grant types can be defined by assigning them a
>    unique absolute URI for use with the "grant_type" parameter.  If the
>    extension grant type requires additional token endpoint parameters,
>    they MUST be registered in the OAuth Parameters registry as described
>    by Section 11.2.

## 8.4 定义授权端点的响应类型 - Defining New Authorization Endpoint Response Types

新的响应类型可参考章节11.3中的流程，注册到Authorization Endpoint Response Types注册表中。响应类型名称比如遵循如下范式：

    response-type  = response-name *( SP response-name )
    response-name  = 1*response-char
    response-char  = "_" / DIGIT / ALPHA

> New response types for use with the authorization endpoint are
>   defined and registered in the Authorization Endpoint Response Types
>   registry following the procedure in Section 11.3.  Response type
>   names MUST conform to the response-type ABNF.
>
>     response-type  = response-name *( SP response-name )
>     response-name  = 1*response-char
>     response-char  = "_" / DIGIT / ALPHA

如果响应类型中包含一个或多个空格，则将其看待为空格分割的响应类型的列表，且顺序无关。多个响应类型的集合按照一种顺序进行注册即可，其它的组合顺序也可以达到相同的效果。

> If a response type contains one or more space characters (%x20), it
>    is compared as a space-delimited list of values in which the order of
>    values does not matter.  Only one order of values can be registered,
>    which covers all other arrangements of the same set of values.

比如，响应类型"token code"在本规范中并未定义，因此可以将其定义为扩展的响应类型，一旦注册，那与其顺序不同的"code token"就不能再注册为新的响应类型，但这两个顺序不同的值都可以同时用来表明同一种响应类型。

> For example, the response type "token code" is left undefined by this
>    specification.  However, an extension can define and register the
>    "token code" response type.  Once registered, the same combination
>    cannot be registered as "code token", but both values can be used to
>    denote the same response type.

## 8.5 Defining Additional Error Codes - 定义额外的错误码

当进行协议扩展时（访问令牌类型扩展、参数扩展以及授权类型扩展等），如果需要额外的错误码与授权码流程错误码、隐式授权模式错误码、令牌错误响应以及资源访问错误响应等配合使用，那这些额外的错误码需要进行定义。

> In cases where protocol extensions (i.e., access token types,
>    extension parameters, or extension grant types) require additional
>    error codes to be used with the authorization code grant error
>    response (Section 4.1.2.1), the implicit grant error response
>    (Section 4.2.2.1), the token error response (Section 5.2), or the
>    resource access error response (Section 7.2), such error codes MAY be
>    defined.

如果扩展的错误码需要与已注册的令牌类型、已注册的端点参数或者一个扩展的授权类型一起使用，那该错误码必须进行注册（遵循章节11.4）。如果与未注册的扩展点配合使用，则可注册也可不注册。

> Extension error codes MUST be registered (following the procedures in
>    Section 11.4) if the extension they are used in conjunction with is a
>    registered access token type, a registered endpoint parameter, or an
>    extension grant type.  Error codes used with unregistered extensions
>    MAY be registered.

错误码必须遵循如下ABNF的范式，如果可能，那在该范式前再增加一个标识前缀。比如，为"example"这个扩展参数增加的标识其无效的扩展错误码，则可以命名为"example_invalid"。

    error      = 1*error-char
    error-char = %x20-21 / %x23-5B / %x5D-7E

> Error codes MUST conform to the error ABNF and SHOULD be prefixed by
>    an identifying name when possible.  For example, an error identifying
>    an invalid value set to the extension parameter "example" SHOULD be
>    named "example_invalid".
>
>      error      = 1*error-char
>      error-char = %x20-21 / %x23-5B / %x5D-7E

# 9. 本地应用 - Native Applications

本地应用是指在资源所有者所使用的设备上安装并执行的客户端（比如桌面应用、手机应用等），本地应用要求额外的有关安全性、平台适应性以及用户体验方面的考量。

> Native applications are clients installed and executed on the device
>    used by the resource owner (i.e., desktop application, native mobile
>    application).  Native applications require special consideration
>    related to security, platform capabilities, and overall end-user
>    experience.

授权端点涉及到客户端和资源所有者的user-agent之间的监护，本地应用客户通过打开外部的user-agent或者应用内置一个user-agent来解决。

比如：

* 外部的user-agent - 本地应用可以通过这些方法来使用重定向URI，以获取授权服务器的响应。如通过在操作系统层面将应用注册为处理器、手动复制粘贴凭证、运行一个本地的web服务器、安装user-agent扩展插件、或者提供一个在客户端掌控下的重定向URI，从而使响应对本机应用程序可用。

* 内置user-agent - 通过与内置浏览器的通讯，本地应用可以获取响应，比如当资源加载时监控状态变化，或者访问user-agent的cookies。

> The authorization endpoint requires interaction between the client
>    and the resource owner's user-agent.  Native applications can invoke
>    an external user-agent or embed a user-agent within the application.
>    For example:
>
>    o  External user-agent - the native application can capture the
>       response from the authorization server using a redirection URI
>       with a scheme registered with the operating system to invoke the
>       client as the handler, manual copy-and-paste of the credentials,
>       running a local web server, installing a user-agent extension, or
>       by providing a redirection URI identifying a server-hosted
>       resource under the client's control, which in turn makes the
>       response available to the native application.
>
>    o  Embedded user-agent - the native application obtains the response
>       by directly communicating with the embedded user-agent by
>       monitoring state changes emitted during the resource load, or
>       accessing the user-agent's cookies storage.

关于如何选择使用外部或内置的user-agent，开发者可考虑如下要素：

* 外部的user-agent可能会提高完成效率，因为资源所有者可能已经在该user-agent中存在有效的会话，无需再次进行认证，这为最终用户提供了统一的体验和功能。资源所有者还可以依赖user-agent的特性和扩展来帮助进行身份认证（比如密码管理器、双因素设备读取器）。

* 内嵌的user-agent可能会提高可用性，因为它无需在新窗口打开，也不涉及上下文的切换。

* 内嵌的user-agent会导致一些安全问题，因为资源所有者会在一个未识别的窗口中进行认证，该窗口无法提供大部分外部user-agent锁支持的保护策略。内嵌的user-agent可能会教导最终用户习惯性信任一些未识别的认证请求（导致更容易进行钓鱼攻击）。

> When choosing between an external or embedded user-agent, developers
>    should consider the following:
>
>    o  An external user-agent may improve completion rate, as the
>       resource owner may already have an active session with the
>       authorization server, removing the need to re-authenticate.  It
>       provides a familiar end-user experience and functionality.  The
>       resource owner may also rely on user-agent features or extensions
>       to assist with authentication (e.g., password manager, 2-factor
>       device reader).
>
>    o  An embedded user-agent may offer improved usability, as it removes
>       the need to switch context and open new windows.
>
>    o  An embedded user-agent poses a security challenge because resource
>       owners are authenticating in an unidentified window without access
>       to the visual protections found in most external user-agents.  An
>       embedded user-agent educates end-users to trust unidentified
>       requests for authentication (making phishing attacks easier to
>       execute).

当选择使用授权码模式还是隐式授权模式时，需进行如下考量：

* 使用授权码类型的本地应用应该在不使用客户端凭证的前提下这样做，因为本地应用无法保障客户端凭证的安全性。

* 使用隐式授权模式时，不会返回刷新令牌，当访问令牌过期时需要重复发起授权流程。

> When choosing between the implicit grant type and the authorization
>    code grant type, the following should be considered:
>
>    o  Native applications that use the authorization code grant type
>       SHOULD do so without using client credentials, due to the native
>       application's inability to keep client credentials confidential.
>
>    o  When using the implicit grant type flow, a refresh token is not
>       returned, which requires repeating the authorization process once
>       the access token expires.
