package io.avaje.oauth2.core.data;

import java.util.Map;

/**
 * Standard Claims as per OpenId specification.
 * <p>
 * Refer to <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">openid.net/specs - StandardClaims</a>
 *
 * @param sub                 Subject - Identifier for the End-User at the Issuer.
 * @param name                End-User's full name in displayable form including all name parts
 * @param givenName           Given name(s) or first name(s) of the End-User
 * @param familyName          Surname(s) or last name(s) of the End-User
 * @param middleName          Middle name(s) of the End-User
 * @param nickname            Casual name of the End-User that may or may not be the same as the given_name
 * @param preferredUsername   Shorthand name by which the End-User wishes to be referred to at the RP
 * @param profile             End-User's profile page
 * @param picture             End-User's profile picture
 * @param website             End-User's Web page or blog
 * @param email               End-User's preferred e-mail address.
 * @param emailVerified       True if the End-User's e-mail address has been verified; otherwise false.
 * @param gender              End-User's gender. Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
 * @param birthdate           End-User's birthday, represented as an ISO 8601-1 [ISO8601‑1] YYYY-MM-DD format
 * @param zoneinfo            String from IANA Time Zone Database
 * @param locale              End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639 Alpha-2 [ISO639] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
 * @param phoneNumber         End-User's preferred telephone number
 * @param phoneNumberVerified True if the End-User's phone number has been verified; otherwise false
 * @param updatedAt           Time the End-User's information was last updated.
 */
public record IdClaims(
        String sub,
        String name,
        String givenName,
        String familyName,
        String middleName,
        String nickname,
        String preferredUsername,
        String profile,
        String picture,
        String website,
        String email,
        boolean emailVerified,
        String gender,
        String birthdate,
        String zoneinfo,
        String locale,
        String phoneNumber,
        boolean phoneNumberVerified,
        long updatedAt,
        // @Json.Unmapped
        Map<String, Object> custom) {
}
