import { useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { postApi } from "../lib/api";
import AttackDetail from "../components/detail/AttackDetail";

/*
AttackDetailPage wraps the AttackDetail component and adds
the feedback submission buttons.

WHY FEEDBACK BUTTONS HERE (not in the component)?
The component shows the data. The PAGE handles user actions.
This separation keeps components "dumb" (display only) and
pages "smart" (handle user interactions and side effects).

WHAT IS queryClient.invalidateQueries?
After submitting feedback, the attack status might change.
We tell React Query "the attacks data is now stale — refetch it."
This way the attacks list updates automatically.
*/
export default function AttackDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();

  const handleFeedback = async (verdict: string) => {
    if (!id) return;

    try {
      await postApi("/v1/feedback", {
        attack_session_id: id,
        verdict,
      });
      alert(
        `Marked as ${verdict.replace("_", " ")}. Thank you!`
      );
      // Refresh attack data
      queryClient.invalidateQueries({
        queryKey: ["attacks"],
      });
      queryClient.invalidateQueries({
        queryKey: ["attack", id],
      });
    } catch (e) {
      alert("Failed to submit feedback");
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">
        Attack Detail
      </h1>

      <AttackDetail />

      {/* Feedback section */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h2 className="text-sm font-semibold text-gray-400 mb-3">
          Was this detection correct?
        </h2>
        <div className="flex gap-3">
          <button
            onClick={() => handleFeedback("true_positive")}
            className="px-4 py-2 bg-green-800 hover:bg-green-700 text-sm rounded-lg transition-colors text-green-200"
          >
            ✅ Yes, correct detection
          </button>
          <button
            onClick={() => handleFeedback("false_positive")}
            className="px-4 py-2 bg-red-800 hover:bg-red-700 text-sm rounded-lg transition-colors text-red-200"
          >
            ❌ No, false positive
          </button>
        </div>
      </div>
    </div>
  );
}