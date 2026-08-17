using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.App.Verification
{
    public sealed class PendingTotpEnrollment
    {
        public required string Username { get; init; }

        public required string EnrollmentUri { get; init; }

        public DateTimeOffset CreatedAt { get; init; }

        public DateTimeOffset ExpiresAt { get; init; }
    }
}
