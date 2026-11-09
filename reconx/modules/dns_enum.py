
import math

import dns.exception
import dns.resolver


DNS_RECORD_TYPES = (
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
)


def enumerate_dns(
    target: str,
    timeout: float = 2.0,
) -> dict:
    """Retrieve common DNS records for a hostname."""

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target hostname cannot be empty.")

    target = target.strip().rstrip(".")

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a finite positive number.")

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results = {}

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(
                target,
                record_type,
                raise_on_no_answer=False,
            )

            if answers.rrset is None:
                results[record_type] = []
                continue

            records = []

            for answer in answers:
                if record_type == "MX":
                    records.append({
                        "priority": answer.preference,
                        "exchange": str(answer.exchange),
                    })
                elif record_type == "TXT":
                    records.append(
                        answer.to_text()
                    )
                else:
                    records.append(
                        answer.to_text()
                    )

            results[record_type] = records

        except dns.resolver.NXDOMAIN:
            results[record_type] = []
            results["error"] = "Domain does not exist."
            break

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            results[record_type] = []

    return {
        "target": target,
        "records": results,
    }
