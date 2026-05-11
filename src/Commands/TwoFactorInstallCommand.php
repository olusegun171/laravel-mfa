<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Commands;

use Illuminate\Console\Command;

class TwoFactorInstallCommand extends Command
{
    protected $signature = 'two-factor:install
                            {--guard=  : The auth guard whose table will receive 2FA columns}
                            {--table=  : Directly specify a table name instead of resolving from a guard}';

    protected $description = 'Generate a migration to add two-factor authentication columns to a table';

    public function handle(): int
    {
        $table = $this->resolveTable();

        if ($table === null) {
            return self::FAILURE;
        }

        $stub      = file_get_contents(__DIR__ . '/../stubs/add_two_factor_columns.stub');
        $migration = str_replace('{{table}}', $table, $stub);

        $filename = date('Y_m_d_His') . '_add_two_factor_to_' . $table . '_table.php';
        $path     = database_path('migrations/' . $filename);

        file_put_contents($path, $migration);

        $this->info("Migration created: <comment>database/migrations/{$filename}</comment>");
        $this->newLine();
        $this->line('  Next: <comment>php artisan migrate</comment>');

        return self::SUCCESS;
    }

    private function resolveTable(): ?string
    {
        if ($table = $this->option('table')) {
            return $table;
        }

        $guard    = $this->option('guard') ?? config('auth.defaults.guard');
        $provider = config("auth.guards.{$guard}.provider");

        if (!$provider) {
            $this->error("Guard [{$guard}] not found in config/auth.php.");
            return null;
        }

        $model = config("auth.providers.{$provider}.model");

        if (!$model) {
            $this->error("Provider [{$provider}] does not use an Eloquent model. Use --table=your_table instead.");
            return null;
        }

        if (!class_exists($model)) {
            $this->error("Model [{$model}] does not exist.");
            return null;
        }

        return (new $model)->getTable();
    }
}
