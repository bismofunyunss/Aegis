using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.App.Verification
{
    public sealed class PendingTotpEnrollmentStore
    {
        private PendingTotpEnrollment? _pending;

        public void Set(
            string username,
            string enrollmentUri,
            TimeSpan lifetime)
        {
            _pending =
                new PendingTotpEnrollment
                {
                    Username = username,
                    EnrollmentUri = enrollmentUri,
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt =
                        DateTimeOffset.UtcNow.Add(
                            lifetime)
                };
        }

        public PendingTotpEnrollment? Get()
        {
            if (_pending == null)
                return null;

            if (_pending.ExpiresAt <=
                DateTimeOffset.UtcNow)
            {
                Clear();

                return null;
            }

            return _pending;
        }

        public void Clear()
        {
            _pending = null;
        }
    }
}
