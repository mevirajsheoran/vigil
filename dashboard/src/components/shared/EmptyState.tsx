interface Props {
  title: string;
  message: string;
}

/*
Empty state shows when there's no data to display (e.g., no attacks detected).

Used on pages where data might not exist yet — makes the dashboard look clean
instead of showing blank space or confusing errors.
*/
export default function EmptyState({ title, message }: Props) {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="flex flex-col items-center gap-3">
        <div className="text-gray-500 text-xl">📭</div>
        <h3 className="text-gray-300 text-lg font-medium">{title}</h3>
        <p className="text-gray-500 text-sm text-center max-w-md">
          {message}
        </p>
      </div>
    </div>
  );
}