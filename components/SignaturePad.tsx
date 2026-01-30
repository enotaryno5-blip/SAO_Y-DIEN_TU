import React, { useRef, useState } from 'react';
import SignatureCanvas from 'react-signature-canvas';
import { Eraser, PenTool } from 'lucide-react';

interface SignaturePadProps {
  onSave: (base64: string | null) => void;
}

const SignaturePad: React.FC<SignaturePadProps> = ({ onSave }) => {
  const sigCanvas = useRef<SignatureCanvas>(null);
  const [isEmpty, setIsEmpty] = useState(true);

  // Cast to any to avoid TypeScript error with props like penColor
  const Canvas = SignatureCanvas as any;

  const clear = () => {
    sigCanvas.current?.clear();
    setIsEmpty(true);
    onSave(null);
  };

  const handleEnd = () => {
    if (sigCanvas.current) {
      setIsEmpty(sigCanvas.current.isEmpty());
      if (!sigCanvas.current.isEmpty()) {
        // Get PNG signature without background
        onSave(sigCanvas.current.getTrimmedCanvas().toDataURL('image/png'));
      }
    }
  };

  return (
    <div className="bg-white p-4 rounded-lg shadow-sm border border-slate-200">
      <div className="flex justify-between items-center mb-2">
        <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
          <PenTool className="w-4 h-4" />
          Chữ ký người chứng thực
        </label>
        <button
          onClick={clear}
          className="text-xs text-red-600 hover:text-red-700 flex items-center gap-1 font-medium"
        >
          <Eraser className="w-3 h-3" />
          Xóa
        </button>
      </div>
      <div className="border border-slate-300 rounded-md bg-white overflow-hidden">
        <Canvas
          ref={sigCanvas}
          penColor="blue"
          canvasProps={{
            width: 300,
            height: 120,
            className: 'cursor-crosshair w-full h-32',
          }}
          onEnd={handleEnd}
        />
      </div>
      <p className="text-xs text-slate-400 mt-2">
        Ký tên vào ô trên. Chữ ký sẽ được chèn vào văn bản.
      </p>
    </div>
  );
};

export default SignaturePad;