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
  loading = false;

  constructor(private eventService: EventService,
  ) {}

  ngOnInit(): void {
    this.seedDataBase();
  }

  seedDataBase() {
    this.loading=true;
    this.eventService.seedDataBase().subscribe({
      next: (data) => {
        console.log('seedDataBase')
        console.log(data)
        this.loading = false;
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się seedDataBase');
      },
    });
  }
}
