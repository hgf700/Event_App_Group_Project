import { Component, OnInit } from '@angular/core';
import { AdminService } from '../../../Services/AdminService';
import { getBoughtTicketDto } from '../../../Dto/getBoughtTicketDto';
import { StatesOfTicket } from '../../../Enum/StatesOfTicket';
import { TicketState } from '../../../Enum/TicketState';

@Component({
  selector: 'app-tickets',
  imports: [],
  templateUrl: './tickets.html',
  styleUrl: './tickets.css',
})
export class Tickets implements OnInit {
  boughtTickets: getBoughtTicketDto[] = [];
  loading = false;

  constructor(
    private adminService: AdminService,
  ) {}

  ngOnInit(): void {
    this.loadBoughtTickets();
  }

  loadBoughtTickets(): void {
    this.loading = true;
    this.adminService.getBoughtTickets().subscribe({
      next: response => {
        this.boughtTickets = response;
        this.loading = false;

      },
      error: err => {
        this.loading = false;
        console.error(err);
      }
    });
  }

  getPaymentStateName(state: StatesOfTicket): string {
    switch (state) {
      case StatesOfTicket.Pending:
        return 'Pending';

      case StatesOfTicket.Paid:
        return 'Paid';

      case StatesOfTicket.Cancelled:
        return 'Cancelled';

      case StatesOfTicket.Expired:
        return 'Expired';

      case StatesOfTicket.Refunded:
        return 'Refunded';

      default:
        return 'Unknown';
    }
  }

  getTicketStateName(state: TicketState): string {
    switch (state) {
      case TicketState.NotIssued:
        return 'Not issued';

      case TicketState.Active:
        return 'Active';

      case TicketState.Used:
        return 'Used';

      case TicketState.Cancelled:
        return 'Cancelled';

      default:
        return 'Unknown';
    }
  }

  formatDate(date: string | null): string {
    if (!date) {
      return '-';
    }

    return new Date(date).toLocaleString('pl-PL');
  }
}
