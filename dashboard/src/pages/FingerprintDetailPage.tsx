import FingerprintDetail from "../components/detail/FingerprintDetail";

/*
FingerprintDetailPage is just a thin wrapper around the
FingerprintDetail component.

WHY SEPARATE PAGE AND COMPONENT?
The detail logic lives in the component (reusable).
The page is just a route target. If we ever want to embed
the fingerprint detail inside another page, we can import
the component directly without the routing wrapper.
*/
export default function FingerprintDetailPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">
        Fingerprint Detail
      </h1>
      <FingerprintDetail />
    </div>
  );
}