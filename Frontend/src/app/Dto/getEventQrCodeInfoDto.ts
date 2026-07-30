export interface getEventQrCodeInfoDto {
  eventId?: string;
  typeOfEvent?: string;
  nameOfEvent?: string;
  startOfEvent: Date;
  address?: string;
  city?: string;
  nameOfClub?: string;
    qrCode?: string;
}