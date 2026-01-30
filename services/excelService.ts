import { CertData } from '../types';

export const generateExcel = (data: CertData): Blob => {
  // Logic: Nếu có tên người ký thì viết hoa và thêm đuôi " - công chứng viên"
  const signerInfo = data.signerName 
    ? `${data.signerName.toUpperCase()} - công chứng viên` 
    : '';

  const htmlContent = `
  <html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
  <head>
    <meta charset="UTF-8">
    <!--[if gte mso 9]>
    <xml>
      <x:ExcelWorkbook>
        <x:ExcelWorksheets>
          <x:ExcelWorksheet>
            <x:Name>SoKhaiBao</x:Name>
            <x:WorksheetOptions>
              <x:DisplayGridlines/>
            </x:WorksheetOptions>
          </x:ExcelWorksheet>
        </x:ExcelWorksheets>
      </x:ExcelWorkbook>
    </xml>
    <![endif]-->
    <style>
      table { border-collapse: collapse; width: 100%; font-family: 'Times New Roman', serif; }
      th, td { border: 1px solid black; padding: 5px; text-align: left; vertical-align: middle; }
      th { font-weight: bold; background-color: #f0f0f0; text-align: center; }
    </style>
  </head>
  <body>
    <table>
      <thead>
        <tr>
          <th>Số thứ tự/ số chứng thực<br>(1)</th>
          <th>Ngày, tháng, năm chứng thực<br>(2)</th>
          <th>Họ tên của người yêu cầu chứng thực<br>(3)</th>
          <th>Tên của bản chính giấy tờ, văn bản<br>(4)</th>
          <th>Họ tên, chức danh người ký chứng thực<br>(5)</th>
          <th>Số bản sao đã được chứng thực<br>(6)</th>
          <th>Lệ phí/ Phí chứng thực<br>(7)</th>
          <th>Ghi chú<br>(8)</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>${data.certNumber || ''}</td>
          <td>Ngày ${data.day} tháng ${data.month} năm ${data.year}</td>
          <td>${data.requestorName || ''}</td>
          <td>${data.documentName || ''}</td>
          <td>${signerInfo}</td>
          <td>${data.copyCount || ''}</td>
          <td>${data.fee || ''}</td>
          <td></td>
        </tr>
      </tbody>
    </table>
  </body>
  </html>`;

  return new Blob([htmlContent], { type: 'application/vnd.ms-excel' });
};