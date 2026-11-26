namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// What a person must do before a device key signs. Fixed when the key is created, because the platforms bind it to
/// the key then.
/// </summary>
public enum DeviceKeyAccess
{
    /// <summary>The key signs without a prompt.</summary>
    None = 0,

    /// <summary>The person confirms presence (a touch or a click) before each signature.</summary>
    UserPresence = 1,

    /// <summary>A biometric check before each signature.</summary>
    Biometry = 2,

    /// <summary>A biometric check, or the device passcode, before each signature.</summary>
    BiometryOrDevicePasscode = 3,

    /// <summary>A biometric check with the biometrics enrolled when the key was created; re-enrolling invalidates
    /// the key.</summary>
    BiometryCurrentSet = 4,
}

/// <summary>
/// What actually protects a device key's private half. A store reports this honestly and never claims more.
/// </summary>
public enum DeviceKeyProtection
{
    /// <summary>The private key is in ordinary memory or on disk, protected by software only.</summary>
    Software = 1,

    /// <summary>The private key is in hardware the operating system cannot read: a TPM, a TEE, a Secure
    /// Enclave.</summary>
    Hardware = 2,

    /// <summary>The private key is in a separate secure element (Android StrongBox).</summary>
    StrongBox = 3,
}

/// <summary>
/// Why a device-key operation did not succeed. Callers act on the category; the message is for people.
/// </summary>
public enum DeviceKeyErrorCategory
{
    /// <summary>The caller cancelled, or the person dismissed a prompt.</summary>
    Cancelled = 1,

    /// <summary>The person tried and failed the prompt's check.</summary>
    UserVerificationFailed = 2,

    /// <summary>The key exists but can never sign again (biometrics re-enrolled, passcode removed). Create and
    /// approve a new key; retrying does not help.</summary>
    KeyInvalidated = 3,

    /// <summary>No key with that scope and alias.</summary>
    KeyNotFound = 4,

    /// <summary>The store cannot do this here: no TPM, a simulator with no secure hardware, or an access policy the
    /// store cannot enforce.</summary>
    NotSupported = 5,

    /// <summary>The request itself is invalid (a malformed scope or alias, empty data).</summary>
    InvalidRequest = 6,

    /// <summary>A key with that scope and alias already exists.</summary>
    AlreadyExists = 7,

    /// <summary>The platform failed in a way none of the other categories describe.</summary>
    PlatformFailure = 8,
}
