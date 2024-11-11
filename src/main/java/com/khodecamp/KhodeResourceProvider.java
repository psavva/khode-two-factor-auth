package com.khodecamp;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class KhodeResourceProvider implements RealmResourceProvider {


    private final KeycloakSession session;

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    // Check if the request is authenticated and has the required permissions
    private AuthResult checkAuth() {
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();

        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        }

        return auth;
    }

    // Check permissions and get user
    private UserModel checkPermissionsAndGetUser(final String userid) {
        AuthResult auth = checkAuth();

        final UserModel user = this.session.users().getUserById(this.session.getContext().getRealm(), userid);
        if (user == null) {
            throw new ForbiddenException("invalid user");
        }
        if (user.getServiceAccountClientLink() != null) {
            throw new ForbiddenException("Cannot manage 2fa of service account");
        }

        return user;
    }

    @GET
    @Path("totp/setup/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Setup TOTP for user",
            description = "This endpoint generates a TOTP secret for the user and returns the secret and QR code."
    )
    @APIResponse(
            responseCode = "200",
            description = "",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    public Response setupTotp(@PathParam("user_id") final String userid) {

        // Check permissions and get user
        final UserModel user = checkPermissionsAndGetUser(userid);
        final RealmModel realm = session.getContext().getRealm();

        // Create TotpBean without UriBuilder as we don't need UI specific URLs
        TotpBean totpBean = new TotpBean(session, realm, user, null);

        // Store the TOTP secret temporarily
        user.setSingleAttribute("temp_totp_secret", totpBean.getTotpSecret());

        OTPPolicy otpPolicy = realm.getOTPPolicy();

        return Response.ok(Map.of(
                "secret", totpBean.getTotpSecretEncoded(),
                "qrCode", totpBean.getTotpSecretQrCode(),
                "policy", Map.of(
                        "algorithm", otpPolicy.getAlgorithm(),
                        "digits", otpPolicy.getDigits(),
                        "period", otpPolicy.getPeriod(),
                        "type", otpPolicy.getType()
                ),
                "supportedApplications", totpBean.getSupportedApplications()
        )).build();
    }

    @POST
    @Path("totp/verify/{user_id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Verify and enable TOTP for user",
            description = "This endpoint verifies the TOTP code and enables TOTP for the user."
    )
    @APIResponse(
            responseCode = "200",
            description = "",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    public Response verifyAndEnableTotp(@PathParam("user_id") final String userid, Map<String, String> data) {
        final UserModel user = checkPermissionsAndGetUser(userid);
        final RealmModel realm = session.getContext().getRealm();
        String code = data.get("code");

        if (code == null || code.trim().isEmpty()) {
            throw new BadRequestException("Code is required");
        }

        String totpSecret = user.getFirstAttribute("temp_totp_secret");
        if (totpSecret == null) {
            throw new BadRequestException("TOTP secret not found. Please setup TOTP first.");
        }

        OTPPolicy otpPolicy = realm.getOTPPolicy();
        HmacOTP hmacOTP = new HmacOTP(
                otpPolicy.getDigits(),
                otpPolicy.getAlgorithm(),
                1  // lookAroundWindow - number of intervals to check
        );

        // Calculate current counter based on current time
        long currentTimeSeconds = System.currentTimeMillis() / 1000;
        int currentCounter = (int) (currentTimeSeconds / otpPolicy.getPeriod());

        // Validate the code
        int newCounter = hmacOTP.validateHOTP(code, totpSecret, currentCounter - 1);
        boolean validCode = newCounter > 0;

        if (!validCode) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Invalid code"))
                    .build();
        }

        // Remove temporary secret
        user.removeAttribute("temp_totp_secret");

        // Create OTP credential
        OTPCredentialModel otpCredential = OTPCredentialModel.createTOTP(
                totpSecret,
                otpPolicy.getDigits(),
                otpPolicy.getPeriod(),
                otpPolicy.getAlgorithm()
        );

        // Store the credential
        user.credentialManager().createStoredCredential(otpCredential);

        return Response.ok(Map.of(
                "message", "TOTP enabled successfully",
                "enabled", true
        )).build();
    }

    @GET
    @Path("totp/status/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Get TOTP status for user",
            description = "This endpoint returns the TOTP status for the user."
    )
    @APIResponse(
            responseCode = "200",
            description = "",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    public Response getTotpStatus(@PathParam("user_id") final String userid) {
        final UserModel user = checkPermissionsAndGetUser(userid);
        final RealmModel realm = session.getContext().getRealm();

        TotpBean totpBean = new TotpBean(session, realm, user, null);

        return Response.ok(Map.of(
                "enabled", totpBean.isEnabled(),
                "credentials", totpBean.getOtpCredentials().stream()
                        .map(credential -> Map.of(
                                "id", credential.getId(),
                                "type", credential.getType(),
                                "createdDate", credential.getCreatedDate()
                        ))
                        .collect(Collectors.toList())
        )).build();
    }

    @POST
    @Path("totp/validate/{user_id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Validate TOTP code",
            description = "This endpoint validates the TOTP code for the user."
    )
    @APIResponse(
            responseCode = "200",
            description = "",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    public Response validateTotp(@PathParam("user_id") final String userid, Map<String, String> data) {
        final UserModel user = checkPermissionsAndGetUser(userid);
        final RealmModel realm = session.getContext().getRealm();
        String code = data.get("code");

        if (code == null || code.trim().isEmpty()) {
            throw new BadRequestException("Code is required");
        }

        // Get TOTP credentials
        var totpCredentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .toList();

        if (totpCredentials.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "TOTP is not enabled for this user"))
                    .build();
        }

        // Get OTP policy
        OTPPolicy otpPolicy = realm.getOTPPolicy();
        TimeBasedOTP timeBasedOTP = new TimeBasedOTP(
                otpPolicy.getAlgorithm(),
                otpPolicy.getDigits(),
                otpPolicy.getPeriod(),
                0
        );

        // Get the first TOTP credential
        OTPCredentialModel credential = OTPCredentialModel.createFromCredentialModel(totpCredentials.getFirst());
        System.out.println("Decoded secret: " + Arrays.toString(credential.getDecodedSecret()));

        // Validate the code
        boolean validCode = timeBasedOTP.validateTOTP(code, credential.getDecodedSecret());

        if (!validCode) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Invalid code"))
                    .build();
        }

        return Response.ok(Map.of(
                "message", "TOTP code validated successfully",
                "valid", true
        )).build();
    }

    @DELETE
    @Path("totp/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Disable TOTP for user",
            description = "This endpoint disables TOTP for the user."
    )
    @APIResponse(
            responseCode = "200",
            description = "",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    public Response disableTotp(@PathParam("user_id") final String userid) {
        final UserModel user = checkPermissionsAndGetUser(userid);

        // Get all TOTP credentials
        var totpCredentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .toList();

        if (totpCredentials.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "TOTP is not enabled for this user"))
                    .build();
        }

        // Remove all TOTP credentials
        totpCredentials.forEach(credential ->
                user.credentialManager().removeStoredCredentialById(credential.getId())
        );

        return Response.ok(Map.of(
                "message", "TOTP disabled successfully",
                "enabled", false
        )).build();
    }
}
