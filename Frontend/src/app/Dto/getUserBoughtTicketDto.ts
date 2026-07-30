export interface getUserBoughtTicketDto {
  eventId: number;
  typeOfEvent?: string;
  nameOfEvent?: string;
  startOfEvent: Date;
  address?: string;
  city?: string;
  nameOfClub?: string;
}