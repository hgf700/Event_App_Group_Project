import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { EventService } from '../../Services/EventService'

@Component({
  selector: 'app-seed-database',
  imports: [CommonModule, RouterModule],
  templateUrl: './seed-database.html',
  styleUrl: './seed-database.css',
})
export class SeedDatabase implements OnInit{
  constructor(
    private eventService: EventService,
  ) {}

  ngOnInit(): void {
    this.seedDataBase();
  }

  seedDataBase() {
    this.eventService.seedDataBase().subscribe({
      next: (data) => {
        console.log('seedDataBase')
        console.log(data)
      },
      error: (err) => {
        console.error(err);
        alert('Nie udało się seedDataBase');
      },
    });
  }
}
