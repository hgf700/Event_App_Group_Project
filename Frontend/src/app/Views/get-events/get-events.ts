import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { ChangeDetectorRef } from '@angular/core';
import { eventDto } from '../../Dto/eventDto'
import { EventService } from '../../Services/EventService'
import { SubEventDetails } from '../sub-event-details/sub-event-details'

@Component({
  selector: 'app-get-events',
  standalone: true,
  imports: [CommonModule, RouterModule,MatDialogModule],
  templateUrl: './get-events.html',
  styleUrl: './get-events.css',
})
export class GetEvents implements OnInit{
  events: eventDto[]=[];
  loading = false;
  
  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private cdr: ChangeDetectorRef,
    private eventService: EventService,
    private dialog: MatDialog,
  ) {}

  ngOnInit(): void {
    this.getEvents();
  }

  eventDetails(eventId: number) {
    const dialogRef = this.dialog.open(SubEventDetails, {
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

  getEvents() {
    this.loading=true;
    this.eventService.getEvents().subscribe({
      next: (data) => {
        this.events = data ?? [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się getEvents');
      },
    });
  }
}
