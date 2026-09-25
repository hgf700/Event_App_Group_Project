export interface getEventDto {
  eventId: number;
  typeOfEvent?: string;
  nameOfEvent?: string;
  urlOfEvent?: string;
  photoUrl?: string;
  startOfEvent: Date;
  address?: string;
  city?: string;
  country?: string;
  nameOfClub?: string;
}
