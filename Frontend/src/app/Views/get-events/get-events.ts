import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { eventDto } from '../../Dto/eventDto'
import { EventService } from '../../Services/EventService'


@Component({
  selector: 'app-get-events',
  imports: [CommonModule, RouterModule],
  templateUrl: './get-events.html',
  styleUrl: './get-events.css',
})
export class GetEvents implements OnInit{
  events: eventDto[]=[];
  
  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private eventService: EventService,
  ) {}

  ngOnInit(): void {
    this.getEvents();
  }

  eventDetails(id: number){
    this.eventService.eventDetails(id).subscribe({
      next: (data) => {
      },
      error: (err) => {
        console.error(err);
        alert('Nie udało się getEvents');
      },
    });
  }

  getEvents() {
    this.eventService.getEvents().subscribe({
      next: (data) => {
        this.events = data;
      },
      error: (err) => {
        console.error(err);
        alert('Nie udało się getEvents');
      },
    });
  }
}
