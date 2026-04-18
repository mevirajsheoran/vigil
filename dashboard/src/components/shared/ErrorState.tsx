interface Props {
  message: string;
  onRetry?: () => void;
}

/*
Error state shows when something goes wrong (API failure, network error).

onRetry: optional function to call when user clicks "Retry" button.
This lets users refresh data without reloading the entire page.
*/
export default function ErrorState({ message, onRetry }: Props) {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="flex flex-col items-center gap-3">
        <div className="text-red-400 text-xl">❌</div>
        <p className="text-gray-400 text-center max-w-md">
          {message}
        </p>
        {onRetry && (
          <button
            onClick={onRetry}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm transition-colors"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  );
}