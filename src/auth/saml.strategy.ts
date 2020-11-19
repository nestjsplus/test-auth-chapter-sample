import { Profile, Strategy } from "passport-saml";
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from "@nestjs/config";
import fs = require('fs');

// example
class User {
  id: string;
  name: string;
  email: string;

  constructor(id, name, email) {
    this.id = id;
    this.name = name;
    this.email = email;
  }
}

@Injectable()
export class SAMLStrategy extends PassportStrategy(Strategy) {
  public constructor(config: ConfigService) {
    super({
      path: "/loginCallback",
      entryPoint: config.get('SAML_ENTRY_POINT') ||
        "https://myservice/auth/realms/service/protocol/saml/clients/urn:service:auth:test",
      privateCert: fs.readFileSync(
        config.get('SAML_PEM_PATH') || "./client-private-key.pem",
        "utf-8"
      ),
      signatureAlgorithm: "sha256",
    });
  }

  public async validate(profile?: Profile): Promise<User> {
    if (!profile) {
      throw new UnauthorizedException();
    } else {
      return new User(
        profile.nameID,
        profile.given_name,
        profile.email
      );
    }
  }
}
