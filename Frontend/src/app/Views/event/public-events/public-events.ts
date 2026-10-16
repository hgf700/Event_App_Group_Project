import { ChangeDetectorRef, Component, inject, OnInit } from '@angular/core';
import { EventService } from '../../../Services/EventService';
import { DatePipe } from '@angular/common';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { getEventDto } from '../../../Dto/getEventDto';

@Component({
  selector: 'app-public-events',
  imports: [DatePipe, MatPaginatorModule],
  templateUrl: './public-events.html',
  styleUrl: './public-events.css',
})
export class PublicEvents implements OnInit {
  events: getEventDto[] = [];
  loading = false;
  totalItems = 0;
  pageSize = 4;
  pageIndex = 0;
  error = false;

  constructor(
    private cdr: ChangeDetectorRef,
    private eventService: EventService,
  ) {}

  ngOnInit(): void {
    this.loadEvents();
  }

  loadEvents(): void {
    this.eventService.getPublicEvents(this.pageIndex + 1, this.pageSize).subscribe((response) => {
      this.events = response.data;
      this.totalItems = response.totalCount;
      this.cdr.detectChanges();
    });
  }

  onPageChange(event: PageEvent) {
    this.pageIndex = event.pageIndex;
    this.pageSize = event.pageSize;

    this.loadEvents();
  }
}
