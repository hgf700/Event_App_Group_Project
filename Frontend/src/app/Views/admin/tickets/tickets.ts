import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { AdminService } from '../../../Services/AdminService';
import { getBoughtTicketDto } from '../../../Dto/getBoughtTicketDto';
import { StatesOfTicket } from '../../../Enum/StatesOfTicket';
import { TicketState } from '../../../Enum/TicketState';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-tickets',
  imports: [FormsModule],
  templateUrl: './tickets.html',
  styleUrl: './tickets.css',
})
export class Tickets implements OnInit {
  boughtTickets: getBoughtTicketDto[] = [];
  loading = false;

  searchText = '';
  filteredTickets: getBoughtTicketDto[] = [];

  constructor(
    private adminService: AdminService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.loadBoughtTickets();
  }

  loadBoughtTickets(): void {
    this.loading = true;
    this.adminService.getBoughtTickets().subscribe({
      next: (response) => {
        this.boughtTickets = response;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
      },
    });
  }

  filterTickets() {
    const search = this.searchText.toLowerCase().trim();

    this.filterTickets = this.boughtTickets.filter(user =>
      user.email.toLowerCase().includes(search) ||
      user.id.toLowerCase().includes(search) 
    );
  }

  clearSearch() {
    this.searchText = '';
    this.filteredUsers = this.users;
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
