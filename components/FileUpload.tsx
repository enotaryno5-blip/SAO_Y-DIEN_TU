import React, { useCallback } from 'react';
import { UploadCloud } from 'lucide-react';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
}

const FileUpload: React.FC<FileUploadProps> = ({ onFileSelect }) => {
  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        const file = e.dataTransfer.files[0];
        if (file.type === 'application/pdf') {
          onFileSelect(file);
        } else {
          alert('Vui lòng chỉ tải lên file PDF.');
        }
      }
    },
    [onFileSelect]
  );

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onFileSelect(e.target.files[0]);
    }
  };

  return (
    <div
      onDrop={handleDrop}
      onDragOver={(e) => e.preventDefault()}
      className="border-2 border-dashed border-slate-300 rounded-lg p-10 flex flex-col items-center justify-center text-center cursor-pointer hover:bg-slate-50 transition-colors bg-white shadow-sm"
    >
      <input
        type="file"
        accept="application/pdf"
        className="hidden"
        id="file-upload"
        onChange={handleChange}
      />
      <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center">
        <div className="bg-blue-50 p-4 rounded-full mb-4">
          <UploadCloud className="w-8 h-8 text-blue-600" />
        </div>
        <h3 className="text-lg font-semibold text-slate-900 mb-1">
          Tải tài liệu PDF
        </h3>
        <p className="text-sm text-slate-500 max-w-xs">
          Kéo thả file vào đây hoặc nhấn để chọn file từ máy tính
        </p>
      </label>
    </div>
  );
};

export default FileUpload;
