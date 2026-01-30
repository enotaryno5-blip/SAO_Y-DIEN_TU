import { PDFDocument, rgb, Color, Grayscale } from 'pdf-lib';
import fontkit from '@pdf-lib/fontkit';
import { CertData, CertPosition } from '../types';

// Font Online: Tinos (Bold) - Tương đương Times New Roman
const FONT_URL = 'https://fonts.gstatic.com/s/tinos/v15/buE4poG45L0m2wn5cn7D.ttf';

const TEXT_COLOR = rgb(0, 0.2, 0.6); // Xanh đậm
const RED_COLOR = rgb(0.8, 0, 0);   // Đỏ
const PLACEHOLDER_COLOR = rgb(0.8, 0.8, 0.8); // Màu xám nhạt cho khung ký

const fetchFont = async (): Promise<ArrayBuffer> => {
  try {
    console.log(`Đang thử tải font online từ: ${FONT_URL}`);
    
    // Tạo Controller để ngắt kết nối nếu mạng lag quá 10 giây
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 giây timeout (Tăng lên để hỗ trợ mạng chậm)

    const response = await fetch(FONT_URL, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.arrayBuffer();
  } catch (err) {
    console.error("Lỗi tải font online:", err);
    throw err;
  }
};

export const modifyPdf = async (
  pdfBytes: Uint8Array,
  certData: CertData,
  signatureImageBase64: string | null,
  customFontBuffer?: ArrayBuffer | null
): Promise<Uint8Array> => {
  try {
    // 1. Load file PDF
    let pdfDoc;
    try {
      pdfDoc = await PDFDocument.load(pdfBytes);
      
      if (fontkit) {
          const fontkitInstance = (fontkit as any).default || fontkit;
          pdfDoc.registerFontkit(fontkitInstance);
      } else {
          console.warn("Cảnh báo: Không tìm thấy thư viện fontkit.");
      }
    } catch (loadError) {
      console.error("Lỗi đọc file PDF:", loadError);
      throw new Error("File PDF bị lỗi hoặc có mật khẩu.");
    }

    // 2. Xử lý Font
    let fontBytes: ArrayBuffer;
    
    if (customFontBuffer) {
        console.log("Sử dụng Font từ người dùng tải lên.");
        fontBytes = customFontBuffer;
    } else {
        try {
            fontBytes = await fetchFont();
        } catch (e) {
            // Ném lỗi rõ ràng để App.tsx bắt được và hiện thông báo yêu cầu upload font
            throw new Error("Không tải được Font Online. Vui lòng tải file Font (.ttf) từ máy tính của bạn vào mục 'Cấu hình nâng cao' bên dưới để tiếp tục.");
        }
    }

    let customFont;
    try {
        customFont = await pdfDoc.embedFont(fontBytes);
    } catch (embedError) {
        console.error(embedError);
        throw new Error("Lỗi xử lý Font. Có thể thư viện fontkit chưa tải được hoặc file font bị lỗi. Hãy thử chọn file font khác (.ttf).");
    }

    // 3. XÁC ĐỊNH TRANG VẼ VÀ VỊ TRÍ
    const pages = pdfDoc.getPages();
    if (pages.length === 0) throw new Error("File PDF không có trang nào.");
    
    let targetPage = pages[pages.length - 1];
    let isNewPage = false;

    // Nếu chọn "Sang trang mới"
    if (certData.position === 'NEW_PAGE_TOP_RIGHT') {
        const { width, height } = targetPage.getSize();
        targetPage = pdfDoc.addPage([width, height]);
        isNewPage = true;
    }

    const { width, height } = targetPage.getSize();

    // --- CẤU HÌNH KÍCH THƯỚC (Giữ nguyên yêu cầu cũ: 9 & 14, Margin 60) ---
    const TITLE_FONT_SIZE = 14; 
    const LABEL_FONT_SIZE = 9; 
    const VALUE_FONT_SIZE = 14; 
    const CONTENT_FONT_SIZE = 9; 

    const LINE_HEIGHT = 16; 
    const LINE_SPACING_FACTOR = 1.0; 
    const marginX = 60; 
    
    // Tính toán chiều cao block để căn vị trí bottom-up
    const contentBlockHeight = (LINE_HEIGHT * 4) + 80 + LINE_HEIGHT + 20;

    let startX = 0;
    let currentY = 0;
    let blockWidth = 0;

    // --- LOGIC VỊ TRÍ ---
    if (isNewPage) {
        startX = width / 2; 
        blockWidth = (width / 2) - marginX;
        currentY = height - 50; 
    } else {
        startX = marginX; 
        blockWidth = (width / 2) - marginX;

        switch (certData.position) {
            case 'TOP_LEFT': // 1. Đầu trang
                currentY = height - 50;
                break;
            case 'ONE_SIXTH_LEFT': // 2. 1/6 Trang
                currentY = height * (5/6);
                break;
            case 'TWO_SIXTHS_LEFT': // 3. 2/6 Trang
                currentY = height * (4/6);
                break;
            case 'THREE_SIXTHS_LEFT': // 4. 3/6 Trang
                currentY = height * (3/6);
                break;
            case 'FOUR_SIXTHS_LEFT': // 5. 4/6 Trang
                currentY = height * (2/6);
                break;
            case 'FIVE_SIXTHS_LEFT': // 6. 5/6 Trang
                currentY = height * (1/6);
                break;
            case 'BOTTOM_LEFT': // 7. Cuối trang (Default)
            default:
                const marginBottom = 30;
                currentY = marginBottom + contentBlockHeight;
                break;
        }
    }
    
    // --- HÀM VẼ TEXT ---
    const drawBoldLine = (text: string, y: number, fontSize: number, color: Color = TEXT_COLOR) => {
        const textWidth = customFont.widthOfTextAtSize(text, fontSize);
        const x = startX + (blockWidth - textWidth) / 2;
        
        targetPage.drawText(text, { x: x, y: y, size: fontSize, font: customFont, color: color });
        targetPage.drawText(text, { x: x + 0.3, y: y, size: fontSize, font: customFont, color: color });
        targetPage.drawText(text, { x: x, y: y + 0.3, size: fontSize, font: customFont, color: color });
    };

    interface TextSegment { text: string; size: number; color: Color; bold: boolean; }
    const drawRichLine = (segments: TextSegment[], y: number) => {
        let totalLineWidth = 0;
        for (const seg of segments) {
            totalLineWidth += customFont.widthOfTextAtSize(seg.text, seg.size);
        }
        let currentX = startX + (blockWidth - totalLineWidth) / 2;
        for (const seg of segments) {
            targetPage.drawText(seg.text, { x: currentX, y: y, size: seg.size, font: customFont, color: seg.color });
            if (seg.bold) {
                targetPage.drawText(seg.text, { x: currentX + 0.3, y: y, size: seg.size, font: customFont, color: seg.color });
                targetPage.drawText(seg.text, { x: currentX, y: y + 0.3, size: seg.size, font: customFont, color: seg.color });
            }
            currentX += customFont.widthOfTextAtSize(seg.text, seg.size);
        }
    };

    // --- BẮT ĐẦU VẼ ---

    // Dòng 1: Tiêu đề
    const title = 'CHỨNG THỰC BẢN SAO ĐÚNG VỚI BẢN CHÍNH';
    drawBoldLine(title, currentY, TITLE_FONT_SIZE); 

    currentY -= LINE_HEIGHT * LINE_SPACING_FACTOR;

    // Dòng 2: Số hiệu & Quyển số
    const gap = "          ";
    const line2Segments: TextSegment[] = [
        { text: "Số chứng thực: ", size: LABEL_FONT_SIZE, color: TEXT_COLOR, bold: true },
        { text: certData.certNumber, size: VALUE_FONT_SIZE, color: RED_COLOR, bold: false },
        { text: `${gap}Quyển số: `, size: LABEL_FONT_SIZE, color: TEXT_COLOR, bold: true },
        { text: certData.bookNumber, size: VALUE_FONT_SIZE, color: RED_COLOR, bold: false },
        { text: " -SCT/BS", size: LABEL_FONT_SIZE, color: TEXT_COLOR, bold: true }
    ];
    drawRichLine(line2Segments, currentY);

    currentY -= LINE_HEIGHT * LINE_SPACING_FACTOR;

    // Dòng 3: Ngày tháng
    const line3 = `Ngày ${certData.day} tháng ${certData.month} năm ${certData.year}`;
    drawBoldLine(line3, currentY, CONTENT_FONT_SIZE);

    currentY -= LINE_HEIGHT * LINE_SPACING_FACTOR;

    // Dòng 4: Người thực hiện
    const line4 = 'Người thực hiện chứng thực';
    drawBoldLine(line4, currentY, CONTENT_FONT_SIZE);

    // --- KHU VỰC CHỮ KÝ ---
    const signatureSpace = 75; 
    const sigZoneWidth = 180;  
    const sigZoneHeight = 60;  
    
    const sigZoneX = startX + (blockWidth - sigZoneWidth) / 2;
    const sigZoneY = currentY - signatureSpace + 15;

    // 1. Vẽ hình ảnh chữ ký nháp (Nếu có) - Nằm dưới cùng
    if (signatureImageBase64) {
      try {
        const pngImage = await pdfDoc.embedPng(signatureImageBase64);
        const pngDims = pngImage.scale(0.3); 
        const imgX = sigZoneX + (sigZoneWidth - pngDims.width) / 2;
        const imgY = sigZoneY + (sigZoneHeight - pngDims.height) / 2;

        targetPage.drawImage(pngImage, { x: imgX, y: imgY, width: pngDims.width, height: pngDims.height });
      } catch (e) { console.warn("Lỗi ảnh chữ ký", e); }
    }

    // 2. Vẽ khung viền placeholder cho Chữ ký số (Visual Guide)
    try {
        targetPage.drawRectangle({
            x: sigZoneX,
            y: sigZoneY,
            width: sigZoneWidth,
            height: sigZoneHeight,
            borderColor: PLACEHOLDER_COLOR,
            borderWidth: 1,
            // dashArray: [4, 4], // Nét đứt (Optional, pdf-lib support vary)
            opacity: 0.5,
        });

        const hintText = "Ký số (Token) tại đây";
        const hintSize = 9;
        const hintWidth = customFont.widthOfTextAtSize(hintText, hintSize);
        targetPage.drawText(hintText, {
            x: sigZoneX + (sigZoneWidth - hintWidth) / 2,
            y: sigZoneY + (sigZoneHeight / 2) - (hintSize / 2),
            size: hintSize,
            font: customFont,
            color: PLACEHOLDER_COLOR,
            opacity: 0.6
        });
    } catch(e) {}

    // 3. Tạo Widget Chữ ký (Clickable Zone) - Nằm trên cùng
    try {
      const form = pdfDoc.getForm();
      const signatureFieldName = `Signature_Cert_${Date.now()}`;
      const signatureField = form.createSignature(signatureFieldName);
      
      // Tạo VisualAppearance cho Widget (trong suốt nhưng có thể click)
      signatureField.addToPage(targetPage, { 
          x: sigZoneX, 
          y: sigZoneY, 
          width: sigZoneWidth, 
          height: sigZoneHeight 
      });
    } catch (sigError) { console.warn("Lỗi tạo Signature Field:", sigError); }

    // ĐÃ XÓA: Phần vẽ tên người ký ở dưới cùng theo yêu cầu

    return await pdfDoc.save();

  } catch (error: any) {
    console.error("Error modifying PDF:", error);
    throw new Error(error.message || "Không thể xử lý file PDF.");
  }
};