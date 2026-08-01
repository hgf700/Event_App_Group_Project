export interface getEventTicketWithQrDto {
  eventId: number;
  typeOfEvent: string;
  nameOfEvent: string;
  startOfEvent: Date;
  address: string;
  city: string;
  nameOfClub: string;
  urlOfEvent: string;
  qrCode: string;
}