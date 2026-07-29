import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { getEventDto } from '../../Dto/getEventDto';
import { UserService } from '../../Services/UserService';
import { EventService } from '../../Services/EventService';
import { SubBoughtEventInfo } from '../sub-bought-event-info/sub-bought-event-info';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';

@Component({
  selector: 'app-user-tickets',
  standalone: true,
  imports: [CommonModule, RouterModule, MatDialogModule],
  templateUrl: './user-tickets.html',
  styleUrl: './user-tickets.css',
})
export class UserTickets implements OnInit{
  events: getEventDto[] = [];
  loading = false;

  constructor(
    private router: Router,
    private cdr: ChangeDetectorRef,
    private dialog: MatDialog,
    private userService: UserService,
    private eventService: EventService,
  ) {}

  ngOnInit(): void {
    this.getUserTickets();
  }

  getUserTickets() {
    this.loading = true;
    this.userService.currentUserTickets().subscribe({
      next: (data) => {
        this.events = data ?? [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się currentUserTickets');
      },
    });
  }

  userBoughtTicketInfo(eventId: number) {
    const dialogRef = this.dialog.open(SubBoughtEventInfo, {
      width: '600px',
      height: '400px',
      data: {
        eventId,
      },
    });

    dialogRef.afterClosed().subscribe((result) => {
      console.log('Dialog closed:', result);
    });
  }

  isTicketActive(startOfEvent?: Date): boolean {
     if (!startOfEvent) {
      return false;
    }

    return new Date(startOfEvent) >= new Date();
  }

  returnToLoginCallback() {
    this.router.navigate(['/login-callback']);
  }
}
