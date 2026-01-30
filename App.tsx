import React, { useState, useEffect } from 'react';
import { FileText, Download, RefreshCw, Book, Hash, AlertCircle, Trash2, FileCheck, Layers, Type, User, FolderOpen, Files, Banknote } from 'lucide-react';

import FileUpload from './components/FileUpload';
import SignaturePad from './components/SignaturePad';
import { CertData, AppState } from './types';
import { modifyPdf } from './services/pdfService';
import { generateExcel } from './services/excelService';

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [fontFile, setFontFile] = useState<File | null>(null);
  const [appState, setAppState] = useState<AppState>(AppState.IDLE);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastDownloadedFile, setLastDownloadedFile] = useState<{url: string, name: string} | null>(null);
  const [savedSigners, setSavedSigners] = useState<string[]>([]);
  const [savedDocNames, setSavedDocNames] = useState<string[]>([]); // New State for Document Name History
  
  // VER 7.0: Track submission attempt
  const [isSubmitted, setIsSubmitted] = useState(false);
  
  const today = new Date();
  const currentMonth = (today.getMonth() + 1).toString().padStart(2, '0');
  const currentYear = today.getFullYear().toString();

  const [certData, setCertData] = useState<CertData>({
    certNumber: '',
    bookNumber: `${currentMonth}/${currentYear}`,
    day: today.getDate().toString().padStart(2, '0'),
    month: currentMonth,
    year: currentYear,
    signerName: '',
    position: 'BOTTOM_LEFT',
    requestorName: '',
    documentName: '',
    copyCount: '',
    fee: ''
  });

  const [signature, setSignature] = useState<string | null>(null);

  useEffect(() => {
    try {
      const stored = localStorage.getItem('savedSigners');
      if (stored) {
        setSavedSigners(JSON.parse(stored));
      }
      
      // Load saved document names
      const storedDocs = localStorage.getItem('savedDocNames');
      if (storedDocs) {
        setSavedDocNames(JSON.parse(storedDocs));
      }
    } catch (e) {
      console.error("Error loading saved data", e);
    }
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setCertData(prev => {
        const newData = { ...prev, [name]: value };
        if (name === 'month' || name === 'year') {
            newData.bookNumber = `${newData.month}/${newData.year}`;
        }
        return newData;
    });
  };

  const handleFontFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.name.endsWith('.ttf') || file.name.endsWith('.otf')) {
        setFontFile(file);
      } else {
        alert("Vui lòng chỉ chọn file font định dạng .ttf hoặc .otf");
      }
    }
  };

  const triggerDownload = (url: string, fileName: string) => {
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const saveSignerToHistory = (name: string) => {
    if (!name || !name.trim()) return;
    const cleanName = name.trim().toUpperCase();
    if (!savedSigners.includes(cleanName)) {
      const newSaved = [cleanName, ...savedSigners].slice(0, 10);
      setSavedSigners(newSaved);
      localStorage.setItem('savedSigners', JSON.stringify(newSaved));
    }
  };
  
  // New function to save document name
  const saveDocNameToHistory = (name: string) => {
    if (!name || !name.trim()) return;
    const cleanName = name.trim(); // Preserve case for documents
    if (!savedDocNames.includes(cleanName)) {
      const newSaved = [cleanName, ...savedDocNames].slice(0, 20); // Keep 20 items
      setSavedDocNames(newSaved);
      localStorage.setItem('savedDocNames', JSON.stringify(newSaved));
    }
  };

  const removeFile = () => {
    setFile(null);
    setAppState(AppState.IDLE);
    setErrorMessage(null);
    setLastDownloadedFile(null);
    setCertData(prev => ({ 
      ...prev, 
      certNumber: '', 
      requestorName: '', 
      documentName: '', 
      copyCount: '', 
      fee: '' 
    })); 
    setSignature(null);
    setIsSubmitted(false);
  };

  const handleProcess = async () => {
    setIsSubmitted(true);
    
    // VALIDATION: Strict check for certNumber
    if (!certData.certNumber || certData.certNumber.trim() === '') {
        setErrorMessage("Lỗi: Vui lòng nhập 'Số chứng thực' để tiếp tục.");
        window.scrollTo({ top: 150, behavior: 'smooth' });
        return;
    }

    if (!file) return;

    setAppState(AppState.PROCESSING);
    setErrorMessage(null);
    setLastDownloadedFile(null);

    try {
      if (certData.signerName) {
        saveSignerToHistory(certData.signerName);
      }
      // Save document name if present
      if (certData.documentName) {
        saveDocNameToHistory(certData.documentName);
      }

      const arrayBuffer = await file.arrayBuffer();
      
      let customFontBuffer = null;
      if (fontFile) {
        customFontBuffer = await fontFile.arrayBuffer();
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      // 1. PDF Generation
      const modifiedBytes = await modifyPdf(
        new Uint8Array(arrayBuffer),
        certData,
        signature,
        customFontBuffer
      );
      
      const blobPdf = new Blob([modifiedBytes], { type: 'application/pdf' });
      const urlPdf = URL.createObjectURL(blobPdf);
      const fileNamePdf = `chung-thuc-${certData.certNumber}.pdf`;

      // 2. Excel Generation (New Feature)
      const blobExcel = generateExcel(certData);
      const urlExcel = URL.createObjectURL(blobExcel);
      const fileNameExcel = `sokhaibao-${certData.certNumber}.xls`;

      triggerDownload(urlPdf, fileNamePdf);
      // Slight delay for second download to ensure browser handles both
      setTimeout(() => triggerDownload(urlExcel, fileNameExcel), 500);
      
      setLastDownloadedFile({ url: urlPdf, name: fileNamePdf });
      setAppState(AppState.SUCCESS);
      
    } catch (error: any) {
      console.error("Processing Error:", error);
      setAppState(AppState.ERROR);
      setErrorMessage(error.message || 'Có lỗi xảy ra khi xử lý PDF.');
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 flex flex-col font-sans">
      <header className="bg-white shadow-sm sticky top-0 z-10">
        <div className="max-w-3xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="bg-blue-600 p-2 rounded-lg">
              <FileText className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-lg font-bold text-slate-800">
              SAO Y ĐIỆN TỬ VER 7.0
            </h1>
          </div>
        </div>
      </header>

      <main className="flex-1 w-full max-w-2xl mx-auto p-4 md:p-8">
        {!file ? (
          <div className="bg-white rounded-xl shadow-md p-8 border border-slate-200 text-center">
             <div className="mb-6">
                <h2 className="text-xl font-bold text-slate-800 mb-2">Tải file PDF cần ký số</h2>
                <p className="text-slate-500 text-sm">Chương trình chạy offline, không lưu file của bạn.</p>
             </div>
             <FileUpload onFileSelect={setFile} />
          </div>
        ) : (
          <div className="flex flex-col gap-6">
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4 flex items-center justify-between">
              <div className="flex items-center gap-3 overflow-hidden">
                <div className="bg-red-100 p-2 rounded-lg flex-shrink-0">
                  <FileText className="w-6 h-6 text-red-600" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-900 truncate max-w-[200px] sm:max-w-md">
                    {file.name}
                  </p>
                  <p className="text-xs text-slate-500">
                    {(file.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
              </div>
              <button 
                onClick={removeFile}
                className="text-slate-400 hover:text-red-500 p-2 hover:bg-slate-50 rounded-full transition-colors"
                title="Xóa file chọn lại"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            </div>

            <div className="bg-white rounded-xl shadow-md border border-slate-200 p-6 md:p-8">
              <h3 className="text-lg font-semibold text-slate-800 mb-6 flex items-center gap-2 border-b pb-2">
                <Book className="w-5 h-5 text-blue-600" />
                Thông tin chứng thực
              </h3>
              
              <div className="space-y-5">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">
                      Số chứng thực <span className="text-red-500">*</span>
                    </label>
                    <div className="relative">
                      <Hash className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                      <input
                        type="text"
                        name="certNumber"
                        value={certData.certNumber}
                        onChange={handleInputChange}
                        placeholder="123"
                        className={`w-full pl-9 pr-3 py-2 border rounded-lg focus:outline-none focus:ring-2 transition-colors
                           ${isSubmitted && !certData.certNumber 
                                ? 'border-red-500 ring-1 ring-red-500 bg-red-50' 
                                : 'border-slate-300 focus:ring-blue-500'}`}
                      />
                    </div>
                    {isSubmitted && !certData.certNumber && (
                        <p className="text-xs text-red-500 mt-1 font-medium">⚠️ Vui lòng nhập số chứng thực!</p>
                    )}
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Quyển số</label>
                    <div className="relative">
                      <Book className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                      <input
                        type="text"
                        name="bookNumber"
                        value={certData.bookNumber}
                        onChange={handleInputChange}
                        placeholder="01/2023"
                        className="w-full pl-9 pr-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Ngày chứng thực</label>
                  <div className="grid grid-cols-3 gap-3">
                    <input
                      type="text"
                      name="day"
                      value={certData.day}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-center"
                      placeholder="Ngày"
                    />
                    <input
                      type="text"
                      name="month"
                      value={certData.month}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-center"
                      placeholder="Tháng"
                    />
                    <input
                      type="text"
                      name="year"
                      value={certData.year}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-center"
                      placeholder="Năm"
                    />
                  </div>
                </div>

                <div>
                   <label className="block text-sm font-medium text-slate-700 mb-1">Người thực hiện chứng thực</label>
                   <input
                      type="text"
                      list="signer-suggestions"
                      name="signerName"
                      value={certData.signerName}
                      onChange={handleInputChange}
                      placeholder="Nhập tên người ký..."
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg uppercase"
                    />
                    <datalist id="signer-suggestions">
                      {savedSigners.map((name, index) => (
                        <option key={index} value={name} />
                      ))}
                    </datalist>
                </div>
                
                {/* NHÓM SỔ THEO DÕI (MỚI) */}
                <div className="border-t border-slate-200 pt-4 mt-2 bg-slate-50 p-3 rounded-lg">
                    <h4 className="text-sm font-bold text-slate-700 mb-3 flex items-center gap-1 uppercase tracking-wider">
                        <Files className="w-4 h-4"/> Thông tin sổ theo dõi (Tùy chọn)
                    </h4>
                    
                    <div className="space-y-3">
                        <div>
                            <label className="block text-xs font-medium text-slate-500 mb-1">Họ tên người yêu cầu</label>
                            <div className="relative">
                                <User className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                                <input name="requestorName" value={certData.requestorName} onChange={handleInputChange} placeholder="Nguyễn Văn A..." className="w-full pl-9 pr-3 py-2 text-sm border border-slate-300 rounded-lg" />
                            </div>
                        </div>
                        
                        <div>
                            <label className="block text-xs font-medium text-slate-500 mb-1">Tên bản chính giấy tờ, văn bản</label>
                            <div className="relative">
                                <FolderOpen className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                                <input 
                                    name="documentName" 
                                    list="doc-suggestions"
                                    value={certData.documentName} 
                                    onChange={handleInputChange} 
                                    placeholder="Căn cước công dân / Bằng đại học..." 
                                    className="w-full pl-9 pr-3 py-2 text-sm border border-slate-300 rounded-lg" 
                                />
                                <datalist id="doc-suggestions">
                                  {savedDocNames.map((name, index) => (
                                    <option key={index} value={name} />
                                  ))}
                                </datalist>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                             <div>
                                <label className="block text-xs font-medium text-slate-500 mb-1">Số bản sao</label>
                                <div className="relative">
                                    <Files className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                                    <input name="copyCount" value={certData.copyCount} onChange={handleInputChange} placeholder="1" className="w-full pl-9 pr-3 py-2 text-sm border border-slate-300 rounded-lg" />
                                </div>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-slate-500 mb-1">Lệ phí / Phí</label>
                                <div className="relative">
                                    <Banknote className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                                    <input name="fee" value={certData.fee} onChange={handleInputChange} placeholder="5.000" className="w-full pl-9 pr-3 py-2 text-sm border border-slate-300 rounded-lg" />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {/* HẾT NHÓM MỚI */}

                <div className="border-t border-slate-200 pt-4">
                  <label className="block text-sm font-medium text-slate-700 mb-1">
                    <div className="flex items-center gap-1">
                      <Layers className="w-4 h-4" /> Vị trí lời chứng
                    </div>
                  </label>
                  <select
                    name="position"
                    value={certData.position}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="TOP_LEFT">1. Đầu trang (Trái)</option>
                    <option value="ONE_SIXTH_LEFT">2. 1/6 Trang (Trái)</option>
                    <option value="TWO_SIXTHS_LEFT">3. 2/6 Trang (Trái)</option>
                    <option value="THREE_SIXTHS_LEFT">4. 3/6 Trang (Trái)</option>
                    <option value="FOUR_SIXTHS_LEFT">5. 4/6 Trang (Trái)</option>
                    <option value="FIVE_SIXTHS_LEFT">6. 5/6 Trang (Trái)</option>
                    <option value="BOTTOM_LEFT">7. Cuối trang (Trái) - Mặc định</option>
                    <option value="NEW_PAGE_TOP_RIGHT">8. Đầu trang sau (Phải)</option>
                  </select>
                </div>

                 <div className="bg-orange-50 p-4 rounded-lg border border-orange-100">
                    <label className="block text-sm font-medium text-orange-800 mb-2 flex items-center gap-2">
                        <Type className="w-4 h-4" /> 
                        Font chữ tiếng Việt (Tùy chọn)
                    </label>
                    <div className="flex items-center gap-2">
                        <input 
                            type="file" 
                            accept=".ttf,.otf"
                            onChange={handleFontFileChange}
                            className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-orange-100 file:text-orange-700 hover:file:bg-orange-200"
                        />
                    </div>
                    {fontFile ? (
                        <p className="text-xs text-green-600 mt-2 font-medium">✓ Đã chọn: {fontFile.name}</p>
                    ) : (
                        <p className="text-xs text-orange-600 mt-2">* Chọn file font nếu không có mạng.</p>
                    )}
                 </div>

                <div className="bg-slate-50 p-4 rounded-lg border border-slate-200">
                    <div className="text-sm font-medium text-slate-700 mb-2 flex justify-between">
                        <span>Chữ ký nháp / Con dấu (Không bắt buộc)</span>
                        <span className="text-xs text-slate-500 font-normal">Chỉ dùng để chèn hình ảnh</span>
                    </div>
                    <SignaturePad onSave={setSignature} />
                </div>

                <div className="pt-4">
                    {errorMessage && (
                       <div className="mb-4 bg-red-50 text-red-700 p-3 rounded-lg text-sm flex items-start gap-2 border border-red-200">
                         <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                         <div>{errorMessage}</div>
                       </div>
                    )}

                    <button
                      onClick={handleProcess}
                      disabled={appState === AppState.PROCESSING}
                      className={`w-full py-4 px-6 rounded-xl text-white font-bold text-lg shadow-lg hover:shadow-xl transition-all flex items-center justify-center gap-2
                        ${appState === AppState.PROCESSING 
                          ? 'bg-blue-400 cursor-wait' 
                          : 'bg-blue-600 hover:bg-blue-700 active:scale-[0.99]'}`}
                    >
                      {appState === AppState.PROCESSING ? (
                        <><RefreshCw className="w-6 h-6 animate-spin" /> Đang xử lý...</>
                      ) : (
                        <><Download className="w-6 h-6" /> Xử lý & Tải về (PDF + Excel)</>
                      )}
                    </button>
                    
                    <p className="text-center text-xs text-slate-400 mt-3">Hệ thống sẽ tải xuống 2 file: PDF (đã ký) và Excel (sổ theo dõi).</p>
                </div>
              </div>
            </div>

            {appState === AppState.SUCCESS && lastDownloadedFile && (
               <div className="bg-green-50 border border-green-200 rounded-xl p-6 flex flex-col items-center text-center animate-bounce-short">
                  <div className="bg-green-100 p-3 rounded-full mb-3"><FileCheck className="w-8 h-8 text-green-600" /></div>
                  <h3 className="text-lg font-bold text-green-800 mb-1">Thành công!</h3>
                  <p className="text-green-700 mb-4 text-sm">Đã tạo file PDF và file Excel sổ theo dõi.</p>
                  
                  <div className="w-full bg-white/60 p-3 rounded border border-green-100 text-left text-sm text-slate-600 mb-4">
                      <p>💡 <strong>Mẹo:</strong> Nếu vị trí chưa đẹp, bạn hãy chỉnh lại mục <strong>"Vị trí lời chứng"</strong> ở trên và bấm nút <strong>"Xử lý & Tải về"</strong> lần nữa.</p>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-3 w-full max-w-md">
                     <button onClick={() => triggerDownload(lastDownloadedFile.url, lastDownloadedFile.name)} className="flex-1 bg-white border border-green-300 text-green-700 py-2 px-4 rounded-lg font-medium hover:bg-green-50 transition-colors flex items-center justify-center gap-2"><Download className="w-4 h-4" /> Tải lại PDF</button>
                     <button onClick={removeFile} className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg font-medium hover:bg-green-700 transition-colors flex items-center justify-center gap-2 shadow-sm"><RefreshCw className="w-4 h-4" /> Làm hồ sơ mới</button>
                  </div>
               </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

export default App;