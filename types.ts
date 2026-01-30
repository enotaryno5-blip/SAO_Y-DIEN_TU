export type CertPosition = 
  | 'TOP_LEFT'            // 1. Đầu trang (Trái)
  | 'ONE_SIXTH_LEFT'      // 2. 1/6 trang (Trái)
  | 'TWO_SIXTHS_LEFT'     // 3. 2/6 trang (Trái)
  | 'THREE_SIXTHS_LEFT'   // 4. 3/6 trang (Trái)
  | 'FOUR_SIXTHS_LEFT'    // 5. 4/6 trang (Trái)
  | 'FIVE_SIXTHS_LEFT'    // 6. 5/6 trang (Trái)
  | 'BOTTOM_LEFT'         // 7. Cuối trang (Trái) - Mặc định
  | 'NEW_PAGE_TOP_RIGHT'; // 8. Đầu trang sau (Phải)

export interface CertData {
  certNumber: string; // Số chứng thực
  bookNumber: string; // Quyển số
  day: string;
  month: string;
  year: string;
  signerName: string;
  position: CertPosition; // Vị trí đặt lời chứng
  
  // New Optional Fields for Excel Export
  requestorName?: string; // Họ tên người yêu cầu chứng thực
  documentName?: string;  // Tên bản chính giấy tờ
  copyCount?: string;     // Số bản sao đã được chứng thực
  fee?: string;           // Lệ phí/ Phí chứng thực
}

export enum AppState {
  IDLE = 'IDLE',
  PROCESSING = 'PROCESSING',
  SUCCESS = 'SUCCESS',
  ERROR = 'ERROR'
}