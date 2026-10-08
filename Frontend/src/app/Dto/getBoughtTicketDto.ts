import { StatesOfTicket } from '../Enum/StatesOfTicket';
import { TicketState } from '../Enum/TicketState';

export interface getBoughtTicketDto {
  userId: string | null;
  userEmail: string | null;

  eventId: number | null;
  eventName: string | null;
  eventDate: string | null;

  createdAt: string;
  paymentStateAt: string | null;
  paymentState: StatesOfTicket;

  ticketStateAt: string | null;
  ticketState: TicketState;

  paymentId: string | null;
}
