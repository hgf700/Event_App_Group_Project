import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { getEventDto } from '../../Dto/getEventDto';
import { EventService } from '../../Services/EventService';
import { SubEventDetails } from '../sub-event-details/sub-event-details';
import {MatPaginatorModule} from '@angular/material/paginator';
import { PageEvent } from '@angular/material/paginator';

@Component({
  selector: 'app-get-events',
  standalone: true,
  imports: [CommonModule, RouterModule, MatDialogModule, MatPaginatorModule],
  templateUrl: './get-events.html',
  styleUrl: './get-events.css',
})
export class GetEvents implements OnInit {
  events: getEventDto[] = [];
  loading = false;
  totalItems = 0;
  pageSize = 10;
  pageIndex = 0;

  constructor(
    private router: Router,
    private cdr: ChangeDetectorRef,
    private eventService: EventService,
    private dialog: MatDialog,
  ) {}

  ngOnInit(): void {
    this.loadEvents();
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

  onPageChange(event: PageEvent) {
    // console.log('PAGE EVENT', event);

    this.pageIndex = event.pageIndex;
    this.pageSize = event.pageSize;

    this.loadEvents();
  }

  loadEvents() : void{
    this.eventService
      .getEvents(this.pageIndex + 1, this.pageSize)
      .subscribe(response => {
        // console.log('RESPONSE', response);
        this.events = response.data;
        this.totalItems = response.totalCount;
        this.cdr.detectChanges();
      });
  }

  returnToLoginCallback() {
    this.router.navigate(['/login-callback']);
  }
}
