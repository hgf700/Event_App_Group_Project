import { Component, OnInit, ChangeDetectorRef, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { AdminService } from '../../Services/AdminService';
import { EventsNavigationService } from '../../RootingServices/EventsNavigationService';
import { UserNavigationService } from '../../RootingServices/UserNavigationService';
import { TicketState } from '../../Enum/TicketState';
import { StatesOfTicket } from '../../Enum/StatesOfTicket';
import { getAppUsageInfoDto } from '../../Dto/getAppUsageInfoDto';
import { getEventAdminDto } from '../../Dto/getEventAdminDto';
import { getAdminUserDto } from '../../Dto/getAdminUserDto';
import { getBoughtTicketDto } from '../../Dto/getBoughtTicketDto';

@Component({
  selector: 'app-admin-panel',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './admin-panel.html',
  styleUrl: './admin-panel.css',
})
export class AdminPanel implements OnInit{
  usageInfo: getAppUsageInfoDto | null = null;
  events: getEventAdminDto[] = [];
  users: getAdminUserDto[] = [];
  blockedUsers: getAdminUserDto[] = [];
  boughtTickets: getBoughtTicketDto[] = [];
  loading = true;

  constructor(
    private adminService: AdminService
  ) {}

  ngOnInit(): void {
    this.loadDashboard();
  }

  loadDashboard(): void {
    this.loading = true;

    this.adminService.getAppUsageInfo().subscribe({
      next: response => {
        this.usageInfo = response;
      },
      error: err => {
        console.error(err);
      }
    });

    this.loadEvents();
    this.loadUsers();
    this.loadBlockedUsers();
    this.loadBoughtTickets();

    this.loading = false;
  }

  loadEvents(): void {
    this.adminService.getEvents().subscribe({
      next: response => {
        this.events = response;
      },
      error: err => {
        console.error(err);
      }
    });
  }

  loadUsers(): void {
    this.adminService.getUsers().subscribe({
      next: response => {
        this.users = response;
      },
      error: err => {
        console.error(err);
      }
    });
  }

  loadBlockedUsers(): void {
    this.adminService.getBlockedUsers().subscribe({
      next: response => {
        this.blockedUsers = response;
      },
      error: err => {
        console.error(err);
      }
    });
  }

  loadBoughtTickets(): void {
    this.adminService.getBoughtTickets().subscribe({
      next: response => {
        this.boughtTickets = response;
      },
      error: err => {
        console.error(err);
      }
    });
  }

  deleteEvent(id: number): void {
    if (!confirm('Czy na pewno chcesz usunąć to wydarzenie?')) {
      return;
    }

    this.adminService.deleteEvent(id).subscribe({
      next: () => {
        this.events = this.events.filter(e => e.id !== id);
      },
      error: err => {
        console.error(err);
        alert('Nie udało się usunąć wydarzenia.');
      }
    });
  }

  blockUser(id: string): void {
    if (!confirm('Czy na pewno chcesz zablokować tego użytkownika?')) {
      return;
    }

    this.adminService.blockUser(id).subscribe({
      next: () => {
        this.loadUsers();
        this.loadBlockedUsers();
      },
      error: err => {
        console.error(err);
        alert('Nie udało się zablokować użytkownika.');
      }
    });
  }

  unblockUser(id: string): void {
    this.adminService.unblockUser(id).subscribe({
      next: () => {
        this.loadUsers();
        this.loadBlockedUsers();
      },
      error: err => {
        console.error(err);
        alert('Nie udało się odblokować użytkownika.');
      }
    });
  }

  deleteUser(id: string): void {
    if (!confirm('Czy na pewno chcesz usunąć tego użytkownika?')) {
      return;
    }

    this.adminService.deleteUser(id).subscribe({
      next: () => {
        this.loadUsers();
        this.loadBlockedUsers();
      },
      error: err => {
        console.error(err);
        alert('Nie udało się usunąć użytkownika.');
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
