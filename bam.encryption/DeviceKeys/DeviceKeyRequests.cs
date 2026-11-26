namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// The request checks every store makes before doing anything, so all stores refuse the same requests with the same
/// categories. Each returns null when the request may proceed.
/// </summary>
internal static class DeviceKeyRequests
{
    internal static DeviceKeyResult<T>? CheckCreate<T>(DeviceKeyCreateRequest? request, IReadOnlyList<DeviceKeyAccess> supported, DeviceKeyProtection protection, CancellationToken cancellationToken, bool disposed)
    {
        DeviceKeyResult<T>? common = CheckCommon<T>(cancellationToken, disposed);
        if (common != null)
        {
            return common;
        }
        if (request == null)
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, "No create request was given.");
        }
        if (!DeviceKeyId.IsValidName(request.Scope))
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"'{request.Scope}' is not a valid scope.");
        }
        if (request.Alias != null && !DeviceKeyId.IsValidName(request.Alias))
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"'{request.Alias}' is not a valid alias.");
        }
        if (!Enum.IsDefined(request.Access))
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"'{request.Access}' is not an access policy.");
        }
        if (!supported.Contains(request.Access))
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.NotSupported, $"This store cannot enforce access '{request.Access}'.");
        }
        if (!Enum.IsDefined(request.MinimumProtection))
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"'{request.MinimumProtection}' is not a protection level.");
        }
        if (request.MinimumProtection > protection)
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.NotSupported, $"This store gives {protection} protection; the request needs at least {request.MinimumProtection}.");
        }
        return null;
    }

    internal static DeviceKeyResult<T>? CheckSign<T>(DeviceKeyId? id, byte[]? data, CancellationToken cancellationToken, bool disposed)
    {
        DeviceKeyResult<T>? checkedId = CheckId<T>(id, cancellationToken, disposed);
        if (checkedId != null)
        {
            return checkedId;
        }
        if (data == null || data.Length == 0)
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, "There is nothing to sign.");
        }
        return null;
    }

    internal static DeviceKeyResult<T>? CheckId<T>(DeviceKeyId? id, CancellationToken cancellationToken, bool disposed)
    {
        DeviceKeyResult<T>? common = CheckCommon<T>(cancellationToken, disposed);
        if (common != null)
        {
            return common;
        }
        if (id == null || !id.IsValid)
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, "The key id is not valid.");
        }
        return null;
    }

    internal static DeviceKeyResult<T>? CheckScope<T>(string? scope, CancellationToken cancellationToken, bool disposed)
    {
        DeviceKeyResult<T>? common = CheckCommon<T>(cancellationToken, disposed);
        if (common != null)
        {
            return common;
        }
        if (!DeviceKeyId.IsValidName(scope))
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"'{scope}' is not a valid scope.");
        }
        return null;
    }

    internal static DeviceKeyResult<T> NotFound<T>(DeviceKeyId id)
    {
        return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.KeyNotFound, $"No key '{id.Alias}' in scope '{id.Scope}'.");
    }

    private static DeviceKeyResult<T>? CheckCommon<T>(CancellationToken cancellationToken, bool disposed)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.Cancelled, "The operation was cancelled.");
        }
        if (disposed)
        {
            return DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.NotSupported, "The store has been disposed.");
        }
        return null;
    }
}
