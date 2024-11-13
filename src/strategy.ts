import axios from "axios";
import { Request } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import { importPKCS8, SignJWT } from "jose";
import NodeRSA from "node-rsa";
import { IntrospectionResponse, Issuer } from "openid-client";
import { Strategy } from "passport";
import { ParsedQs } from "qs";

interface ZitadelJwtProfile {
  type: "application";
  keyId: string;
  key: string;
  appId: string;
  clientId: string;
}

type AuthorizationConfig =
  | {
      type: "basic";
      clientId: string;
      clientSecret: string;
    }
  | {
      type: "jwt-profile";
      profile: ZitadelJwtProfile;
    };

export interface ZitadelIntrospectionOptions {
  authority: string;
  authorization: AuthorizationConfig;
  discoveryEndpoint?: string;
  introspectionEndpoint?: string;
  issuer?: Issuer;
}

export class ZitadelIntrospectionStrategy extends Strategy {
  public name = "zitadel-introspection";

  private issuer: Issuer | undefined;
  private introspectionEndpoint: string;
  private tokenIntrospector?: (token: string) => Promise<IntrospectionResponse>;

  constructor(private readonly options: ZitadelIntrospectionOptions) {
    super();
    this.issuer = options.issuer;
    this.introspectionEndpoint = options.introspectionEndpoint || "";
  }

  public static async create(
    options: ZitadelIntrospectionOptions
  ): Promise<ZitadelIntrospectionStrategy> {
    const issuer = await Issuer.discover(
      options.discoveryEndpoint ?? options.authority
    );
    options.issuer = issuer;
    return new ZitadelIntrospectionStrategy(options);
  }

  private get clientId(): string {
    return this.options.authorization.type === "basic"
      ? this.options.authorization.clientId
      : this.options.authorization.profile.clientId;
  }

  async authenticate(
    req: Request<
      ParamsDictionary,
      unknown,
      unknown,
      ParsedQs,
      Record<string, any>
    >
  ): Promise<void> {
    const authHeader = req.headers?.authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
      this.fail({ message: "No bearer token found" });
      return;
    }

    this.tokenIntrospector ??= await this.createTokenIntrospector();

    const token = authHeader.substring(7);

    try {
      const result = await this.tokenIntrospector(token);
      if (!result.active) {
        this.fail({ message: "Token is not active" });
        return;
      }

      this.success(result);
    } catch (error) {
      (this.error ?? console.error)(error);
    }
  }

  private async createTokenIntrospector(): Promise<
    (token: string) => Promise<IntrospectionResponse>
  > {
    if (!this.introspectionEndpoint) {
      if (!this.issuer) {
        this.issuer = await Issuer.discover(
          this.options.discoveryEndpoint ?? this.options.authority
        );
      }
      this.introspectionEndpoint = this.issuer.metadata[
        "introspection_endpoint"
      ] as string;
    }

    let jwt = "";
    let lastCreated = 0;

    const getPayload = async (
      token: string
    ): Promise<Record<string, string>> => {
      if (this.options.authorization.type === "basic") {
        return { token };
      }

      if (this.isJwtExpired(lastCreated)) {
        jwt = await this.createNewJwt();
        lastCreated = Date.now();
      }

      return {
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: jwt,
        token,
      };
    };

    return async (token: string): Promise<IntrospectionResponse> => {
      const payload = await getPayload(token);
      const response = await this.makeIntrospectionRequest(payload);
      return response.data as IntrospectionResponse;
    };
  }

  private isJwtExpired(lastCreated: number): boolean {
    const oneHourInMs = 60 * 60 * 1000;
    return lastCreated < Date.now() - oneHourInMs;
  }

  private async createNewJwt(): Promise<string> {
    if (this.options.authorization.type !== "jwt-profile") {
      throw new Error("JWT profile is not configured");
    }

    const { key, keyId } = this.options.authorization.profile;
    const rsa = new NodeRSA(key);
    const privateKey = await importPKCS8(
      rsa.exportKey("pkcs8-private-pem"),
      "RSA256"
    );

    return new SignJWT({
      iss: this.clientId,
      sub: this.clientId,
      aud: this.options.authority,
    })
      .setIssuedAt()
      .setExpirationTime("1h")
      .setProtectedHeader({
        alg: "RS256",
        kid: keyId,
      })
      .sign(privateKey);
  }

  private async makeIntrospectionRequest(payload: Record<string, string>) {
    const config =
      this.options.authorization.type === "basic"
        ? {
            auth: {
              username: this.options.authorization.clientId,
              password: this.options.authorization.clientSecret,
            },
          }
        : {};

    return axios.post(
      this.introspectionEndpoint,
      new URLSearchParams(payload),
      config
    );
  }
}
