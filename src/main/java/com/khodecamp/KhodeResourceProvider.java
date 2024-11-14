package com.khodecamp;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
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

import java.util.Map;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@JBossLog
public class KhodeResourceProvider implements RealmResourceProvider {


    private final KeycloakSession session;
    // Response codes
    private static final int CODE_SUCCESS = 0;
    private static final int CODE_INVALID_USER_ID = 1;
    private static final int CODE_INVALID_CODE = 2;
    private static final int CODE_TOTP_NOT_ENABLED = 3;
    private static final int CODE_TOTP_ALREADY_ENABLED = 4;
    private static final int CODE_SERVER_ERROR = 5;
    private static final int CODE_TOTP_SETUP_REQUIRED = 6;
    private static final int CODE_INVALID_TOTP = 7;
    private static final int CODE_OPERATION_FAILED = 8;

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

        // Check if the request is authenticated
        final UserModel user = this.session.users().getUserById(this.session.getContext().getRealm(), userid);
        if (user == null) {
            throw new ForbiddenException("invalid user");
        }
        if (user.getServiceAccountClientLink() != null) {
            throw new ForbiddenException("Service account not allowed");
        }

        return user;
    }

    // New private helper methods
    private Response validateUserId(String userid) {
        if (userid == null || userid.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "Invalid user ID",
                            "code", CODE_INVALID_USER_ID
                    ))
                    .build();
        }
        return null;
    }

    private Response validateTotpCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Code is required", "code", CODE_INVALID_CODE))
                    .build();
        }
        return null;
    }

    private Response checkTotpEnabled(UserModel user, boolean shouldBeEnabled) {
        var totpCredentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .toList();

        boolean hasTotp = !totpCredentials.isEmpty();

        if (shouldBeEnabled && !hasTotp) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "TOTP is not enabled for this user",
                            "code", CODE_TOTP_NOT_ENABLED
                    ))
                    .build();
        }

        if (!shouldBeEnabled && hasTotp) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "TOTP is already configured for this user",
                            "code", CODE_TOTP_ALREADY_ENABLED
                    ))
                    .build();
        }

        return null;
    }

    private Response handleServerError(String operation, String userid, Exception e) {
        log.error("Error while " + operation + " for user: " + userid, e);
        return Response.serverError()
                .entity(Map.of("error", "Internal server error", "code", CODE_SERVER_ERROR))
                .build();
    }

    @GET
    @Path("totp/is-configured/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Check if TOTP is configured for user")
    @APIResponse(responseCode = "200", description = "TOTP status retrieved successfully")
    @APIResponse(responseCode = "400", description = "Invalid user ID")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response isTotpConfigured(@PathParam("user_id") final String userid) {
        Response validation = validateUserId(userid);
        if (validation != null) return validation;

        try {
            final UserModel user = checkPermissionsAndGetUser(userid);
            boolean hasTotp = user.credentialManager()
                    .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .findAny()
                    .isPresent();

            return Response.ok(Map.of(
                    "configured", hasTotp,
                    "message", hasTotp ? "TOTP is configured for this user" : "TOTP is not configured for this user",
                    "userId", userid,
                    "code", CODE_SUCCESS
            )).build();
        } catch (Exception e) {
            return handleServerError("checking TOTP configuration", userid, e);
        }
    }

    @POST
    @Path("totp/setup/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Setup TOTP for user")
    @APIResponse(responseCode = "200", description = "TOTP setup successful")
    @APIResponse(responseCode = "400", description = "Invalid user ID or TOTP already configured")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response setupTotp(@PathParam("user_id") final String userid) {
        Response validation = validateUserId(userid);
        if (validation != null) return validation;

        try {
            final UserModel user = checkPermissionsAndGetUser(userid);

            // Check if TOTP is already configured
            validation = checkTotpEnabled(user, false);
            if (validation != null) return validation;

            final RealmModel realm = session.getContext().getRealm();
            TotpBean totpBean = new TotpBean(session, realm, user, null);
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
                    "supportedApplications", totpBean.getSupportedApplications(),
                    "userId", userid,
                    "code", CODE_SUCCESS
            )).build();
        } catch (Exception e) {
            return handleServerError("setting up TOTP", userid, e);
        }
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
        Response validation = validateUserId(userid);
        if (validation != null) return validation;

        final UserModel user = checkPermissionsAndGetUser(userid);
        final RealmModel realm = session.getContext().getRealm();
        String code = data.get("code");

        validation = validateTotpCode(code);
        if (validation != null) return validation;

        String totpSecret = user.getFirstAttribute("temp_totp_secret");
        if (totpSecret == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "TOTP setup required",
                            "code", CODE_TOTP_SETUP_REQUIRED
                    )).build();
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
                    .entity(Map.of("error", "Invalid code", "code", CODE_INVALID_TOTP))
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
                "enabled", true,
                "code", CODE_SUCCESS
        )).build();
    }

    @GET
    @Path("totp/status/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Get TOTP status for user")
    @APIResponse(responseCode = "200", description = "TOTP status retrieved successfully")
    @APIResponse(responseCode = "400", description = "Invalid user ID")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response getTotpStatus(@PathParam("user_id") final String userid) {
        Response validation = validateUserId(userid);
        if (validation != null) return validation;

        try {
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
                            .collect(Collectors.toList()),
                    "userId", userid,
                    "code", CODE_SUCCESS
            )).build();
        } catch (Exception e) {
            return handleServerError("getting TOTP status", userid, e);
        }
    }

    @POST
    @Path("totp/validate/{user_id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Validate TOTP code")
    @APIResponse(responseCode = "200", description = "TOTP code validated successfully")
    @APIResponse(responseCode = "400", description = "Invalid user ID or code")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response validateTotp(@PathParam("user_id") final String userid, Map<String, String> data) {
        Response validation = validateUserId(userid);
        if (validation != null) return validation;

        try {
            validation = validateTotpCode(data.get("code"));
            if (validation != null) return validation;

            final UserModel user = checkPermissionsAndGetUser(userid);
            validation = checkTotpEnabled(user, true);
            if (validation != null) return validation;

            final RealmModel realm = session.getContext().getRealm();
            OTPPolicy otpPolicy = realm.getOTPPolicy();
            TimeBasedOTP timeBasedOTP = new TimeBasedOTP(
                    otpPolicy.getAlgorithm(),
                    otpPolicy.getDigits(),
                    otpPolicy.getPeriod(),
                    0
            );

            var totpCredentials = user.credentialManager()
                    .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .toList();
            OTPCredentialModel credential = OTPCredentialModel.createFromCredentialModel(totpCredentials.getFirst());

            if (!timeBasedOTP.validateTOTP(data.get("code"), credential.getDecodedSecret())) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error", "Invalid code", "code", CODE_INVALID_TOTP))
                        .build();
            }

            return Response.ok(Map.of(
                    "message", "TOTP code validated successfully",
                    "valid", true,
                    "userId", userid,
                    "code", CODE_SUCCESS
            )).build();
        } catch (Exception e) {
            return handleServerError("validating TOTP code", userid, e);
        }
    }

    @DELETE
    @Path("totp/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @APIResponse(
            responseCode = "200",
            description = "TOTP disabled successfully",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    @APIResponse(
            responseCode = "400",
            description = "TOTP not enabled or invalid user ID"
    )
    @APIResponse(
            responseCode = "500",
            description = "Internal server error"
    )
    @Operation(
            summary = "Disable TOTP for user",
            description = "This endpoint disables TOTP for the user."
    )
    public Response disableTotp(@PathParam("user_id") final String userid) {
        Response validation = validateUserId(userid);
        if (validation != null) return validation;

        try {
            final UserModel user = checkPermissionsAndGetUser(userid);

            // Get all TOTP credentials
            var totpCredentials = user.credentialManager()
                    .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .toList();

            if (totpCredentials.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                "error", "TOTP is not enabled for this user",
                                "code", CODE_TOTP_NOT_ENABLED
                        ))
                        .build();
            }

            // Remove all TOTP credentials
            for (var credential : totpCredentials) {
                try {
                    user.credentialManager().removeStoredCredentialById(credential.getId());
                    log.info("TOTP credential removed for user: " + userid);
                } catch (Exception e) {
                    log.info("Failed to remove TOTP credential for user: " + userid);
                    return Response.serverError()
                            .entity(Map.of("error", "Failed to disable TOTP", "code", CODE_OPERATION_FAILED))
                            .build();
                }
            }

            return Response.ok(Map.of(
                    "message", "TOTP disabled successfully",
                    "enabled", false,
                    "userId", userid,
                    "code", CODE_SUCCESS
            )).build();
        } catch (Exception e) {
            return handleServerError("disabling TOTP", userid, e);
        }
    }

    @POST
    @Path("totp/disable-with-validation/{user_id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Disable TOTP with validation for user",
            description = "This endpoint validates TOTP before disabling it for the user"
    )
    @APIResponse(
            responseCode = "200",
            description = "TOTP disabled successfully",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    @APIResponse(responseCode = "400", description = "TOTP not enabled, invalid code, or invalid user ID")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response disableTotpWithValidation(@PathParam("user_id") final String userid, Map<String, String> data) {
        Response validation = validateUserId(userid);
        if (validation != null) return validation;

        try {
            validation = validateTotpCode(data.get("code"));
            if (validation != null) return validation;

            final UserModel user = checkPermissionsAndGetUser(userid);

            // Check if TOTP is enabled
            validation = checkTotpEnabled(user, true);
            if (validation != null) return validation;

            // Validate TOTP code
            final RealmModel realm = session.getContext().getRealm();
            OTPPolicy otpPolicy = realm.getOTPPolicy();
            TimeBasedOTP timeBasedOTP = new TimeBasedOTP(
                    otpPolicy.getAlgorithm(),
                    otpPolicy.getDigits(),
                    otpPolicy.getPeriod(),
                    0
            );

            var totpCredentials = user.credentialManager()
                    .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .toList();
            OTPCredentialModel credential = OTPCredentialModel.createFromCredentialModel(totpCredentials.getFirst());

            if (!timeBasedOTP.validateTOTP(data.get("code"), credential.getDecodedSecret())) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error", "Invalid code", "code", CODE_INVALID_TOTP))
                        .build();
            }

            // Remove all TOTP credentials after validation
            for (var cred : totpCredentials) {
                try {
                    user.credentialManager().removeStoredCredentialById(cred.getId());
                    log.info("TOTP credential removed for user: " + userid);
                } catch (Exception e) {
                    log.error("Failed to remove TOTP credential for user: " + userid, e);
                    return Response.serverError()
                            .entity(Map.of("error", "Failed to disable TOTP", "code", CODE_OPERATION_FAILED))
                            .build();
                }
            }

            return Response.ok(Map.of(
                    "message", "TOTP validated and disabled successfully",
                    "enabled", false,
                    "userId", userid,
                    "code", CODE_SUCCESS
            )).build();

        } catch (Exception e) {
            return handleServerError("disabling TOTP with validation", userid, e);
        }
    }
}
